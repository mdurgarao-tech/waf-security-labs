# Cross-Site Scripting (XSS) — WAF Protection

## Attack concept

The attacker gets the application to return attacker-controlled script that then
runs in another user's browser, in the context of the trusted site. With that,
they can steal session cookies, perform actions as the victim, or deface/redirect
the page.

Three types a WAF should recognise:
- **Reflected** — payload comes in a request (e.g. a search term) and is echoed
  straight back into the response.
- **Stored** — payload is saved (comment, profile field) and served to every
  later viewer. Highest impact.
- **DOM-based** — the injection happens entirely in client-side JavaScript; the
  malicious data may never reach the server in a form the WAF sees, which is why
  WAFs are weaker here (see limitation below).

Canonical test payload: `<script>alert(1)</script>`, plus event-handler and
attribute-based variants like `<img src=x onerror=alert(1)>` and
`" onmouseover="alert(1)`.

## Detection logic

The WAF inspects inputs for HTML/JS injection signals:
- Script tags and event handlers: `<script`, `onerror=`, `onload=`,
  `onmouseover=`.
- JavaScript URI schemes: `javascript:`.
- HTML that shouldn't appear in a given parameter: `<iframe`, `<svg`, `<img`
  with handlers.
- Encoded variants: `%3Cscript%3E`, HTML entities, unicode escapes — again,
  **normalise before matching**.

## Blocking approach

- Enable the managed XSS ruleset; run detection-first, then block.
- Anomaly scoring again beats single-signal blocking.
- Be especially careful with parameters that are *meant* to accept rich text
  (see tuning) — those need scoped handling, not a blanket block.

## Tuning / testing notes

**Where false positives come from:** applications that legitimately accept HTML
or markup — a CMS body field, a rich-text comment, a "paste your code" box, a
field where users write things like `if a < b then`. The `<` character and
tag-like text trip XSS rules.

**How to avoid them:**
- Identify rich-text parameters during baselining and scope exceptions to those
  specific fields.
- Where the app *needs* HTML input, the real control is server-side output
  encoding and a sanitiser (e.g. an allow-list HTML sanitiser) — the WAF should
  not try to fully own this or it will either over-block or be bypassed.

**How to test (in a lab):**
- Confirm `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>` are
  blocked and logged.
- Confirm a benign message containing `<` or the word "script" in prose is **not**
  blocked.

## Real-world limitation to state honestly

WAFs are strongest on reflected/stored XSS where the payload transits the server
in an inspectable form. **DOM-based XSS** can execute entirely client-side
without a server round-trip the WAF can see, so WAF coverage is partial. The
durable fixes are context-aware output encoding, a Content-Security-Policy (CSP)
header, and input sanitisation in the app. The WAF is a strong outer layer, not
the whole answer.
