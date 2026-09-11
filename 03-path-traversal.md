# Path Traversal / Local File Inclusion (LFI) — WAF Protection

## Attack concept

The attacker manipulates a file path parameter to escape the intended directory
and read files they shouldn't — `/etc/passwd`, application config, source code,
credentials. Local File Inclusion goes further: if the app *includes/executes*
the referenced file, traversal can lead to code execution.

Classic payloads:
- `../../../../etc/passwd`
- `..%2f..%2f..%2fetc%2fpasswd` (URL-encoded)
- `....//....//` (defeats naive single-pass `../` stripping)

## Detection logic

The WAF looks for directory-traversal sequences and sensitive-file references in
inputs used as paths or filenames:
- `../` and `..\` and their encoded forms (`%2e%2e%2f`, double-encoded).
- Known target files: `etc/passwd`, `boot.ini`, `web.config`, `.env`.
- Null-byte and truncation tricks in older stacks.

**Normalisation is the whole game here.** Attackers rely on the WAF and the app
decoding paths differently. A good engine canonicalises the path (decode, resolve
`.` and `..`, collapse slashes) before matching. Weak filters that strip `../`
once are beaten by `....//`.

## Blocking approach

- Enable the managed LFI/path-traversal rule group; detection-first, then block.
- Where a parameter should only ever be a filename from a known set, the
  strongest control is an **allow-list** at the app (map an ID to a filename)
  rather than trying to filter every traversal variant.

## Tuning / testing notes

**False positives** are rarer here than SQLi/XSS but happen where paths
legitimately contain dots or encoded characters — some SPAs and file APIs. Check
during baselining; scope exceptions to the specific route.

**Testing (lab):**
- Confirm `../../../../etc/passwd` and its encoded forms are blocked/logged.
- Confirm a legitimate filename request (e.g. `report-2025.pdf`) passes.

## Real-world limitation

The WAF blocks known traversal patterns; the robust fix is the app never using
user input directly as a filesystem path — use an allow-list / indirect
reference map, run with least privilege, and keep sensitive files outside the web
root.
