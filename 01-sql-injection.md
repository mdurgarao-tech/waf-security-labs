# SQL Injection (SQLi) — WAF Protection

## Attack concept

The attacker injects SQL syntax into an input that the application concatenates
into a database query. The goal is to change the query's meaning — bypass
authentication, read data they shouldn't (other users' records, credentials),
modify or delete data, or in some cases reach the underlying OS.

Classic example against a login form that builds:

```
SELECT * FROM users WHERE user = '<input>' AND pass = '<input>'
```

Supplying `' OR '1'='1' -- ` as the username turns the WHERE clause into
something always true and comments out the rest, bypassing the password check.

Common categories a WAF must handle:
- **In-band** (error-based, UNION-based) — results come back in the response.
- **Blind** (boolean / time-based, e.g. `... AND SLEEP(5)`) — inferred from
  app behaviour or response timing.

## Detection logic

A WAF detects SQLi by inspecting request inputs (query string, POST body,
headers, cookies, JSON values) for SQL meta-characters and keyword patterns in
contexts where they don't belong. Signals include:

- SQL keywords in user input: `UNION SELECT`, `OR 1=1`, `INSERT`, `DROP`,
  `information_schema`.
- Comment sequences used to truncate queries: `--`, `#`, `/* */`.
- Tautologies: `' OR '1'='1`, `" OR ""="`.
- Time-based functions: `SLEEP(`, `BENCHMARK(`, `WAITFOR DELAY`.
- Stacked queries: a `;` followed by another statement.

Good WAF engines normalise input first (URL-decode, strip comments,
resolve encodings) **before** matching, because attackers hide payloads with
encoding — e.g. `%27` for `'`, double-encoding, inline comments like
`UN/**/ION`. Detection that runs before normalisation is trivially bypassed.

## Blocking approach

- Deploy the managed SQLi ruleset (OWASP CRS on ModSecurity; the equivalent
  managed rule group on Imperva / AWS WAF / Azure WAF / Cloudflare).
- Run in **detection mode first**, watch what it flags against real traffic,
  then move to blocking once confident.
- Apply an **anomaly-scoring** model where available (OWASP CRS default): each
  suspicious signal adds to a score; the request is blocked only when the total
  crosses a threshold. This is more robust than blocking on any single keyword,
  which is what causes false positives.

## Tuning / testing notes

**Where false positives come from:** legitimate inputs that happen to contain
SQL-like text. A user writing "I ordered a table and 2 chairs; select the oak
one" contains `table` and `select`. A search box, a comment field, or a code
snippet in a support ticket will trip naive keyword rules.

**How to avoid them:**
- Prefer anomaly scoring over single-keyword blocking.
- Scope exceptions to the *specific parameter* that legitimately carries
  free text (e.g. a `comments` field), not the whole rule globally.
- Use paranoia levels (in OWASP CRS) deliberately: higher levels catch more but
  false-positive more. Start moderate, raise per-application after baselining.

**How to test safely (in a lab):**
- Send known payloads (`' OR '1'='1' -- `, `1 UNION SELECT null,null -- `) to a
  test endpoint and confirm the WAF blocks and logs them with the expected rule
  ID.
- Send benign inputs that resemble SQL (the "select the oak table" example) and
  confirm they are **not** blocked. This second test is the one that matters —
  anyone can block; the skill is not over-blocking.

## Real-world limitation to state honestly

Signature/score-based WAF SQLi protection is strong against automated and
opportunistic attacks but a determined attacker can craft obfuscated payloads to
evade it. The WAF reduces risk and buys time; the durable fix is
**parameterised queries / prepared statements** in the application. A WAF in
front of vulnerable code is mitigation, not a cure.
