# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The MFA setup QR code: inline SVG drawn from the vendored generator."""
import hashlib
from pathlib import Path

from tools import qr_svg, totp
from tools.vendor import qrcodegen

ROOT = Path(__file__).resolve().parent.parent
# sha256 of tools/vendor/qrcodegen.py as committed: upstream v1.8.0
# (720f62bddb7226106071d4728c292cb1df519ceb) plus one added header line.
RECORDED_SHA256 = '697a30659fa1a0cfc59f0c6d923a6156e752d5c9189e4d5b5bb5702c04d451e9'


def test_an_otpauth_uri_renders_as_one_inline_svg_path():
    svg = qr_svg.qr_svg(totp.otpauth_uri(totp.new_secret(), 'owner@client.example'))
    assert svg.startswith('<svg') and svg.count('<path') == 1
    assert 'script' not in svg.lower() and 'href' not in svg.lower()


def test_the_matrix_matches_the_vendored_generator():
    q = qrcodegen.QrCode.encode_text('otpauth://totp/x?secret=ABC', qrcodegen.QrCode.Ecc.MEDIUM)
    assert f'viewBox="0 0 {q.get_size() + 8} {q.get_size() + 8}"' in qr_svg.qr_svg('otpauth://totp/x?secret=ABC')


def test_the_vendored_file_is_the_recorded_upstream_file():
    assert hashlib.sha256((ROOT / 'tools/vendor/qrcodegen.py').read_bytes()).hexdigest() == RECORDED_SHA256
