# Copyright 2026 Daviyon Daniels
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Refresh the enrichment cache: the one code path that reaches CISA, EPSS and NVD.

`tools/enrichment.py` only reads the cache and never touches the network
(constraint 7). This module is how the cache gets filled, and it is run on
purpose (`update-enrichment`, `scripts/fetch-enrichment.py`), never during a
cycle. Standard library only.

Everything downloaded is untrusted bytes. Each download is capped, parsed and
shape-checked before it replaces the existing file, so a malformed or hostile
response counts as a failure and leaves the previous file in place. Files are
written to a temporary name and moved into place with `os.replace`. The NVD
API key is passed to `get` as a header and is never written to disk or logged.
"""

import csv
import gzip
import io
import json
import logging
import math
import os
import re
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

USER_AGENT = "remediation-zero/0.1 (contact via GitHub)"

#: Unauthenticated NVD allows ~5 requests per rolling 30s; with a key, 50.
NVD_DELAY_SECONDS = 6.5
NVD_DELAY_WITH_KEY_SECONDS = 0.7

#: Each download, and each decompressed EPSS body, is refused above this size.
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 30

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
_FLUSH_EVERY = 10

logger = logging.getLogger("remediation_zero.enrichment_fetch")

Get = Callable[..., bytes]


def workspace_cache_dir(root: Path) -> Path:
    """Where a local workspace keeps its enrichment cache."""
    return Path(root) / "enrichment"


def urllib_get(url: str, headers: Optional[dict] = None) -> bytes:
    """The real fetcher: https only, explicit timeout, size capped."""
    if not url.startswith("https://"):
        raise ValueError("enrichment sources are fetched over https only")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        data = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError("download larger than the size cap")
    return data


def _write_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _parse_kev(raw: bytes) -> dict:
    if len(raw) > MAX_DOWNLOAD_BYTES:
        raise ValueError("too large")
    payload = json.loads(raw)
    entries = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(entries, list) or not all(
            isinstance(e, dict) and isinstance(e.get("cveID"), str) for e in entries):
        raise ValueError("not a KEV catalogue")
    return payload


def _parse_epss(raw: bytes, wanted: set) -> dict:
    if len(raw) > MAX_DOWNLOAD_BYTES:
        raise ValueError("too large")
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as handle:
        text = handle.read(MAX_DOWNLOAD_BYTES + 1)
    if len(text) > MAX_DOWNLOAD_BYTES:
        raise ValueError("decompressed larger than the size cap")
    lines = [ln for ln in text.decode("utf-8").splitlines() if not ln.startswith("#")]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not {"cve", "epss", "percentile"} <= set(reader.fieldnames or ()):
        raise ValueError("unexpected EPSS columns")
    rows = 0
    scores = {}
    for row in reader:
        epss, percentile = float(row["epss"]), float(row["percentile"])
        if not (0.0 <= epss <= 1.0 and 0.0 <= percentile <= 1.0) or math.isnan(epss + percentile):
            raise ValueError("EPSS score out of range")
        rows += 1
        if row["cve"] in wanted:
            scores[row["cve"]] = {"epss": epss, "percentile": percentile}
    if rows == 0:
        raise ValueError("no EPSS rows")
    return scores


def _nvd_record(raw: bytes) -> dict:
    if len(raw) > MAX_DOWNLOAD_BYTES:
        raise ValueError("too large")
    payload = json.loads(raw)
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        raise ValueError("not an NVD response")
    if not vulns:
        return {"_not_found": True}
    record = vulns[0].get("cve") if isinstance(vulns[0], dict) else None
    if not isinstance(record, dict):
        raise ValueError("not an NVD record")
    return record


def refresh(cves: Iterable[str], cache_dir: Path, *, get: Get,
            sleep: Callable[[float], None] = time.sleep,
            nvd_api_key: Optional[str] = None) -> dict:
    """Fetch KEV, EPSS and NVD for `cves` into `cache_dir`.

    `get(url)` returns the body bytes; for NVD with a key it is called as
    `get(url, headers={"apiKey": key})`. A source that fails keeps its previous
    file. NVD is resumable: a CVE already cached is skipped, a failed one is
    not cached, so the next run retries it.
    """
    cache_dir = Path(cache_dir)
    wanted = list(dict.fromkeys(cves))
    result: dict = {"kev": "failed", "epss": "failed", "nvd_fetched": 0,
                    "nvd_failed": [], "nvd_skipped": 0}

    try:
        _write_atomic(cache_dir / "cisa_kev.json", _parse_kev(get(KEV_URL)))
        result["kev"] = "ok"
    except Exception as exc:  # noqa: BLE001 - class only; the previous file stays
        logger.info(json.dumps({"event": "enrichment_source_failed", "source": "kev",
                                "error_class": type(exc).__name__}, sort_keys=True))

    try:
        keep = set(wanted)
        kev = _read_json(cache_dir / "cisa_kev.json")
        if isinstance(kev, dict) and isinstance(kev.get("vulnerabilities"), list):
            keep |= {v["cveID"] for v in kev["vulnerabilities"]
                     if isinstance(v, dict) and isinstance(v.get("cveID"), str)}
        previous = _read_json(cache_dir / "epss.json")
        if isinstance(previous, dict):
            keep |= set(previous)
        _write_atomic(cache_dir / "epss.json", _parse_epss(get(EPSS_URL), keep))
        result["epss"] = "ok"
    except Exception as exc:  # noqa: BLE001
        logger.info(json.dumps({"event": "enrichment_source_failed", "source": "epss",
                                "error_class": type(exc).__name__}, sort_keys=True))

    nvd_path = cache_dir / "nvd.json"
    cached = _read_json(nvd_path)
    cached = cached if isinstance(cached, dict) else {}
    # An entry left by the old fetch script as an error is retried, not trusted.
    todo = []
    for cve in wanted:
        entry = cached.get(cve)
        if isinstance(entry, dict) and not entry.get("_error"):
            result["nvd_skipped"] += 1
        elif not _CVE_ID.match(cve):
            result["nvd_failed"].append(cve)
        else:
            todo.append(cve)

    delay = NVD_DELAY_WITH_KEY_SECONDS if nvd_api_key else NVD_DELAY_SECONDS
    headers = {"apiKey": nvd_api_key} if nvd_api_key else None
    unsaved = 0
    try:
        for index, cve in enumerate(todo):
            try:
                url = NVD_URL.format(cve=cve)
                cached[cve] = _nvd_record(get(url, headers=headers) if headers else get(url))
                result["nvd_fetched"] += 1
                unsaved += 1
            except Exception as exc:  # noqa: BLE001 - one bad CVE never stops the rest
                result["nvd_failed"].append(cve)
                logger.info(json.dumps({"event": "enrichment_source_failed", "source": "nvd",
                                        "cve_id": cve, "error_class": type(exc).__name__},
                                       sort_keys=True))
            if unsaved >= _FLUSH_EVERY:
                _write_atomic(nvd_path, cached)
                unsaved = 0
            if index < len(todo) - 1:
                sleep(delay)
    finally:
        if unsaved:
            _write_atomic(nvd_path, cached)
    return result
