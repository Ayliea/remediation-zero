# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Render text as an inline SVG QR code for the authenticator-app setup page.

Uses the vendored Nayuki generator. The output is one <path> of dark modules
inside a 4-module quiet zone: no script, no links, no external references.
"""
from tools.vendor import qrcodegen

QUIET_ZONE = 4


def qr_svg(text: str) -> str:
    """Return an <svg> element drawing `text` as a QR code at error correction level M."""
    qr = qrcodegen.QrCode.encode_text(text, qrcodegen.QrCode.Ecc.MEDIUM)
    size = qr.get_size()
    parts = []
    for y in range(size):
        for x in range(size):
            if qr.get_module(x, y):
                parts.append(f'M{x + QUIET_ZONE},{y + QUIET_ZONE}h1v1h-1z')
    total = size + 2 * QUIET_ZONE
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" '
        f'shape-rendering="crispEdges" role="img" aria-label="QR code">'
        f'<rect width="{total}" height="{total}" fill="#fff"/>'
        f'<path d="{"".join(parts)}" fill="#000"/></svg>'
    )
