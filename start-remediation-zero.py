# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Start the same portable application from a checkout or installed bundle."""
import sys

if __name__ == '__main__':
    if sys.version_info < (3, 12):
        raise SystemExit('Python 3.12 or newer is required. No application files were changed.')
    from scripts.local_launcher import main
    main()
