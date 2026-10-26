# Third-party notices

The local edition is standard-library only, with one bundled exception.

## QR Code generator library (Python)

- Project: Nayuki QR Code generator (Project Nayuki)
- Version: v1.8.0, commit `720f62bddb7226106071d4728c292cb1df519ceb`
- URL: https://github.com/nayuki/QR-Code-generator (`python/qrcodegen.py`)
- Licence: MIT; text in `tools/vendor/QRCODEGEN_LICENSE.txt` and in the file header
- Vendored at: `tools/vendor/qrcodegen.py`, unmodified apart from one added first line naming the upstream tag and commit
- Used by: `tools/qr_svg.py`, to draw the authenticator-app setup code
