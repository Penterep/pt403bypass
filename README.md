[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)

## PT403BYPASS

Testing tool for identifying 401/403 bypass opportunities in web applications. It loads payload lists from `templates/` (verbs, headers, IPs, user agents, path fuzz strings, extensions, default credentials, and other `*.txt` lists) and runs grouped tests similar in spirit to byp4xx, with Penterep-style output.

Bypass detection treats **401** and **403** as blocked responses (fixed in code). **`-s`** / **`-e`** only affect **what is printed** in the terminal, not which tests run.

## Installation

```
pip install pt403bypass
```

## Usage examples

```
pt403bypass -u https://example.com/admin
pt403bypass -u https://example.com/private -vv
pt403bypass -u https://example.com/secret -s 200 -m 500
pt403bypass -u https://example.com/secret -e 404
```

Without **`-s`**, only result lines whose HTTP status **differs from the baseline** are printed. **`-s 200`** prints only lines (and the baseline URL line, if applicable) whose status is in the given list. **`-e 404`** hides lines (and baseline) with those codes. **`-s`** and **`-e`** can be combined (must pass both filters). Use **`-vv`** / **`--verbose`** to print every line when **`-s`** is not set.

## Options

```
-u   --url                         Protected URL to test
-p   --proxy                       Set proxy (e.g. http://127.0.0.1:8080)
-T   --timeout                     Set timeout in seconds (default 10)
-c   --cookie                      Set cookie
-a   --user-agent                  Set User-Agent header
-H   --headers                     Set custom header(s) as header:value
-r   --redirects                   Follow redirects (default False)
-s   --show-status                 Only print lines with these HTTP status codes (optional)
-e   --hide-status                 Do not print lines with these HTTP status codes (e.g. hide 404)
-x   --methods                     HTTP methods (default: templates/verbs.txt); merged with verbs.txt
-m   --max-tests                   Limit number of payload tests (0 = unlimited)
-C   --cache                       Cache compatibility flag (ptlibs)
-vv  --verbose                     Enable verbose mode (show all result lines when -s is not set)
-v   --version                     Show script version and exit
-h   --help                        Show help and exit
-j   --json                        Output in JSON format
     --templates-dir               Directory for *.txt templates (default: package templates/)
```

Path-heavy payloads (built-in paths, mid/end path lists, extensions, case tricks, extra tricks) are sent with **ptlibs `RawHttpClient`** when available so encoded paths are not normalized like `requests`/urllib3.

## Dependencies

```
ptlibs
```

## Warning

Run this tool only against systems you are explicitly authorized to test.
