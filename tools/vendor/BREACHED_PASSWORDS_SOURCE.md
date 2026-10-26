# Bundled breached-password list

- File: `breached_passwords.txt`
- Source: SecLists, `Passwords/Common-Credentials/Pwdb_top-1000000.txt`
  (https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/Pwdb_top-1000000.txt)
- Licence: MIT, Copyright (c) 2018 Daniel Miessler (SecLists). Compatible with Apache 2.0.
- Fetched: 2026-10-26
- Filter: each line NFKC-normalised and lowercased; kept only if 12 to 128
  characters long (shorter passwords are refused by length already); duplicates
  removed (first occurrence wins, so source popularity order is preserved);
  output capped at 1.9 MB (the filter did not reach the cap: 29,954 entries,
  about 427 KB).
- One entry per line, UTF-8. Comparison in `tools/passwords.py` is
  case-insensitive after NFKC normalisation.

MIT licence text for the source list:

> Copyright (c) 2018 Daniel Miessler
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of
> this software and associated documentation files (the "Software"), to deal in
> the Software without restriction, including without limitation the rights to
> use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
> of the Software, and to permit persons to whom the Software is furnished to do
> so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
