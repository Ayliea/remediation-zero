# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Enrichment refresh: the one place that fetches, tested with a fake `get`."""
import csv
import gzip
import io
import json
import logging

import pytest

from tools.enrichment import EnrichmentCache
from tools.enrichment_fetch import (EPSS_URL, KEV_URL, MAX_DOWNLOAD_BYTES, NVD_URL,
                                    refresh, urllib_get, workspace_cache_dir)

KEV = {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dueDate": "2021-12-24"}]}
KEY = "synthetic-nvd-key-9f3a"


def epss_gz(rows=(("CVE-2021-44228", "0.97", "0.99"), ("CVE-2020-0001", "0.1", "0.2"))):
    out = io.StringIO()
    out.write("#model_version:v2025.03.14,score_date:2026-01-01T00:00:00Z\n")
    writer = csv.writer(out)
    writer.writerow(["cve", "epss", "percentile"])
    writer.writerows(rows)
    return gzip.compress(out.getvalue().encode())


def nvd_payload(cve):
    return json.dumps({"vulnerabilities": [{"cve": {"id": cve, "descriptions": [
        {"lang": "en", "value": "Synthetic."}]}}]}).encode()


def fake_get(calls, *, fail=(), kev=None, epss=None):
    def get(url, headers=None):
        calls.append((url, headers))
        if url == KEV_URL:
            return json.dumps(KEV).encode() if kev is None else kev
        if url == EPSS_URL:
            return epss_gz() if epss is None else epss
        cve = url.split("cveId=")[1]
        if cve in fail:
            raise TimeoutError("synthetic")
        return nvd_payload(cve)
    return get


def no_sleep(seconds):
    return None


def test_workspace_cache_dir(tmp_path):
    assert workspace_cache_dir(tmp_path) == tmp_path / "enrichment"


def test_refresh_writes_all_three_and_resumes(tmp_path):
    calls = []
    first = refresh(["CVE-2021-44228"], tmp_path, get=fake_get(calls), sleep=no_sleep)
    assert first["kev"] == "ok" and first["epss"] == "ok" and first["nvd_fetched"] == 1
    again = refresh(["CVE-2021-44228"], tmp_path, get=fake_get(calls), sleep=no_sleep)
    assert again["nvd_skipped"] == 1 and again["nvd_fetched"] == 0
    cache = EnrichmentCache(tmp_path)
    assert cache.has_kev and cache.has_epss and cache.has_nvd
    # EPSS keeps only the CVEs asked about (plus KEV), not the whole dataset.
    assert set(json.loads((tmp_path / "epss.json").read_text())) == {"CVE-2021-44228"}


def test_one_failing_cve_does_not_stop_the_rest(tmp_path):
    cves = ["CVE-2021-44228", "CVE-2020-0001", "CVE-2019-0708"]
    result = refresh(cves, tmp_path, get=fake_get([], fail={"CVE-2020-0001"}), sleep=no_sleep)
    assert result["nvd_failed"] == ["CVE-2020-0001"] and result["nvd_fetched"] == 2
    assert set(json.loads((tmp_path / "nvd.json").read_text())) == {"CVE-2021-44228", "CVE-2019-0708"}
    # The failure is not cached, so the next run retries it.
    retry = refresh(cves, tmp_path, get=fake_get([]), sleep=no_sleep)
    assert retry["nvd_fetched"] == 1 and retry["nvd_skipped"] == 2 and retry["nvd_failed"] == []


def test_invalid_cve_ids_are_failed_and_never_requested(tmp_path):
    calls = []
    result = refresh(["CVE-2021-44228&x=1", "not-a-cve"], tmp_path, get=fake_get(calls),
                     sleep=no_sleep)
    assert sorted(result["nvd_failed"]) == ["CVE-2021-44228&x=1", "not-a-cve"]
    assert not [u for u, _ in calls if "cveId" in u]


def test_failed_kev_download_keeps_the_previous_file(tmp_path):
    refresh([], tmp_path, get=fake_get([]), sleep=no_sleep)
    before = (tmp_path / "cisa_kev.json").read_bytes()
    for bad in (b"not json", b'{"vulnerabilities": "x"}', b"[]",
                b'{"vulnerabilities": [{"nope": 1}]}',
                b"x" * (MAX_DOWNLOAD_BYTES + 1)):
        result = refresh([], tmp_path, get=fake_get([], kev=bad), sleep=no_sleep)
        assert result["kev"] == "failed"
        assert (tmp_path / "cisa_kev.json").read_bytes() == before

    def raising(url, headers=None):
        raise OSError("down")
    assert refresh([], tmp_path, get=raising, sleep=no_sleep)["kev"] == "failed"
    assert (tmp_path / "cisa_kev.json").read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cisa_kev.json", "epss.json"]


def test_malformed_epss_keeps_the_previous_file(tmp_path):
    refresh([], tmp_path, get=fake_get([]), sleep=no_sleep)
    before = (tmp_path / "epss.json").read_bytes()
    for bad in (b"not gzip", gzip.compress(b"a,b\n1,2\n"),
                gzip.compress(b"cve,epss,percentile\nCVE-2021-44228,high,0.2\n"),
                gzip.compress(b"cve,epss,percentile\n"),
                gzip.compress(b"cve,epss,percentile\nCVE-2021-44228,7,0.2\n")):
        assert refresh([], tmp_path, get=fake_get([], epss=bad), sleep=no_sleep)["epss"] == "failed"
        assert (tmp_path / "epss.json").read_bytes() == before
    good = gzip.compress(b"cve,epss,percentile\nCVE-2021-44228,0.1,0.2\n")
    assert refresh([], tmp_path, get=fake_get([], epss=good), sleep=no_sleep)["epss"] == "ok"


def test_oversized_epss_decompression_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr("tools.enrichment_fetch.MAX_DOWNLOAD_BYTES", 1000)
    big = gzip.compress(b"cve,epss,percentile\n" + b"CVE-2021-44228,0.1,0.2\n" * 500)
    assert len(big) < 1000
    assert refresh([], tmp_path, get=fake_get([], epss=big), sleep=no_sleep)["epss"] == "failed"


def test_delay_is_longer_without_a_key(tmp_path):
    sleeps = []
    refresh(["CVE-2021-44228", "CVE-2020-0001"], tmp_path, get=fake_get([]), sleep=sleeps.append)
    assert sleeps == [6.5]
    sleeps.clear()
    refresh(["CVE-2019-0708", "CVE-2018-0001"], tmp_path, get=fake_get([]), sleep=sleeps.append,
            nvd_api_key=KEY)
    assert sleeps == [0.7]


def test_api_key_is_sent_as_header_and_never_logged(tmp_path, caplog):
    calls = []
    caplog.set_level(logging.DEBUG)
    refresh(["CVE-2021-44228"], tmp_path, get=fake_get(calls, fail={"CVE-2021-44228"}),
            sleep=no_sleep, nvd_api_key=KEY)
    refresh(["CVE-2020-0001"], tmp_path, get=fake_get(calls), sleep=no_sleep, nvd_api_key=KEY)
    nvd_calls = [(u, h) for u, h in calls if "cveId" in u]
    assert nvd_calls and all(h == {"apiKey": KEY} for _, h in nvd_calls)
    assert all(h is None for u, h in calls if "cveId" not in u)
    assert KEY not in caplog.text
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert KEY.encode() not in path.read_bytes()


def test_urls_are_https():
    assert KEV_URL.startswith("https://") and EPSS_URL.startswith("https://")
    assert NVD_URL.startswith("https://")


def _fake_transport(monkeypatch, responder):
    """Stand in for the network below urllib's own redirect handling."""
    import urllib.request
    from urllib.response import addinfourl
    from email.message import Message

    import tools.enrichment_fetch as mod
    seen = []

    class Fake(urllib.request.HTTPSHandler, urllib.request.HTTPHandler):
        def __init__(self):
            pass

        def _open(self, req):
            seen.append((req.full_url, dict(req.header_items()), req.timeout))
            code, headers, body = responder(req)
            msg = Message()
            for k, v in headers.items():
                msg[k] = v
            resp = addinfourl(io.BytesIO(body), msg, req.full_url, code)
            resp.msg = "x"
            return resp
        https_open = http_open = _open

    monkeypatch.setattr(mod, "_TRANSPORT_HANDLERS", (Fake(),))
    return seen


def test_real_get_refuses_non_https(monkeypatch):
    with pytest.raises(ValueError):
        urllib_get("http://example.invalid/x")


def test_real_get_has_a_timeout_and_a_size_cap(monkeypatch):
    seen = _fake_transport(monkeypatch, lambda r: (200, {}, b"x" * (MAX_DOWNLOAD_BYTES + 10)))
    with pytest.raises(ValueError):
        urllib_get("https://example.invalid/x", headers={"apiKey": "k"})
    assert seen[0][2] == 30 and seen[0][1]["Apikey"] == "k"


def test_a_redirect_is_refused_and_the_key_never_follows_it(monkeypatch, caplog, tmp_path):
    caplog.set_level(logging.DEBUG)
    seen = _fake_transport(monkeypatch, lambda r: (302, {"Location": "http://evil.invalid/x"}, b""))
    with pytest.raises(Exception) as err:
        urllib_get("https://example.invalid/x", headers={"apiKey": KEY})
    assert len(seen) == 1 and seen[0][0].startswith("https://")
    assert KEY not in str(err.value)
    # Through refresh: a failed fetch, the previous file kept, nothing logged with the key.
    refresh(["CVE-2021-44228"], tmp_path, get=fake_get([]), sleep=no_sleep)
    before = (tmp_path / "cisa_kev.json").read_bytes()
    result = refresh(["CVE-2020-0001"], tmp_path, get=urllib_get, sleep=no_sleep, nvd_api_key=KEY)
    assert result["kev"] == "failed" and result["nvd_failed"] == ["CVE-2020-0001"]
    assert (tmp_path / "cisa_kev.json").read_bytes() == before
    assert all(url.startswith("https://") for url, _, _ in seen)
    assert KEY not in caplog.text


def test_cve_check_rejects_trailing_newline_and_non_ascii_digits(tmp_path):
    calls = []
    bad = ["CVE-2021-44228\n", "CVE-\u0662021-44228"]
    result = refresh(bad, tmp_path, get=fake_get(calls), sleep=no_sleep)
    assert sorted(result["nvd_failed"]) == sorted(bad)
    assert not [u for u, _ in calls if "cveId" in u]


def test_an_nvd_record_for_a_different_cve_is_not_cached(tmp_path):
    def get(url, headers=None):
        if "cveId" in url:
            return nvd_payload("CVE-1999-0001")
        return fake_get([])(url)
    result = refresh(["CVE-2021-44228"], tmp_path, get=get, sleep=no_sleep)
    assert result["nvd_failed"] == ["CVE-2021-44228"] and result["nvd_fetched"] == 0
    assert not (tmp_path / "nvd.json").exists()


def test_source_selection_skips_the_others_and_makes_no_request(tmp_path):
    calls = []
    result = refresh(["CVE-2021-44228"], tmp_path, get=fake_get(calls), sleep=no_sleep, sources=["kev"])
    assert (result["kev"], result["epss"]) == ("ok", "skipped") and result["nvd_fetched"] == 0
    assert [u for u, _ in calls] == [KEV_URL]
    calls.clear()
    result = refresh(["CVE-2021-44228"], tmp_path, get=fake_get(calls), sleep=no_sleep, sources=["nvd"])
    assert result["kev"] == "skipped" and result["nvd_fetched"] == 1
    assert [u for u, _ in calls] == [NVD_URL.format(cve="CVE-2021-44228")]


def _load_script():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "fetch_enrichment_script", Path(__file__).resolve().parents[1] / "scripts" / "fetch-enrichment.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fetch_script_prints_its_lines_and_always_exits_zero(tmp_path, monkeypatch, capsys):
    script = _load_script()
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([{"cve_id": f"CVE-2021-{n:05d}"} for n in range(1, 12)]))
    monkeypatch.setattr(script, "FINDINGS", findings)
    monkeypatch.setattr(script, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(script, "urllib_get", fake_get([]))
    import functools
    monkeypatch.setattr(script, "refresh", functools.partial(refresh, sleep=no_sleep))
    monkeypatch.setattr("sys.argv", ["fetch-enrichment.py"])
    assert script.main() == 0
    out = capsys.readouterr().out
    assert "Populating enrichment cache for 11 distinct CVEs." in out
    assert "  KEV : 1 entries -> cisa_kev.json" in out
    assert "  EPSS: 1 scores -> epss.json" in out
    assert "  NVD : 0 already cached, 11 to fetch" in out
    assert "    10/11 cached" in out and "    11/11 cached" in out
    monkeypatch.setattr("sys.argv", ["fetch-enrichment.py", "kev"])
    assert script.main() == 0
    out = capsys.readouterr().out
    assert "KEV :" in out and "EPSS:" not in out and "NVD :" not in out
    monkeypatch.setattr(script, "urllib_get", lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
    assert script.main() == 0
