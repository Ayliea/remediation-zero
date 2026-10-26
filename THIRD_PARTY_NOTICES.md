# Third-party notices

The local edition is standard-library only, apart from two bundled third-party
works: one library and one data file.

## QR Code generator library (Python)

- Project: Nayuki QR Code generator (Project Nayuki)
- Version: v1.8.0, commit `720f62bddb7226106071d4728c292cb1df519ceb`
- URL: https://github.com/nayuki/QR-Code-generator (`python/qrcodegen.py`)
- Licence: MIT; text in `tools/vendor/QRCODEGEN_LICENSE.txt` and in the file header
- Vendored at: `tools/vendor/qrcodegen.py`, unmodified apart from one added first line naming the upstream tag and commit
- Used by: `tools/qr_svg.py`, to draw the authenticator-app setup code

## Breached-password list (data)

- Project: SecLists (Daniel Miessler), `Passwords/Common-Credentials/Pwdb_top-1000000.txt`
- URL: https://github.com/danielmiessler/SecLists
- Licence: MIT, Copyright (c) 2018 Daniel Miessler; text in `tools/vendor/BREACHED_PASSWORDS_SOURCE.md`
- Bundled at: `tools/vendor/breached_passwords.txt`, a filtered extract (NFKC-normalised, lowercased,
  12 to 128 characters, duplicates removed); the filter is described in the same file
- Used by: `tools/passwords.py`, to refuse a new password that is on the list
