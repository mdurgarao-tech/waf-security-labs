# Command Injection (RCE) — WAF Protection

## Attack concept

The application passes user input into an OS command (shell, system call). The
attacker injects shell metacharacters to run their own commands on the server —
one of the highest-severity outcomes, since it can mean full host compromise.

Example: a "ping host" feature that runs `ping <input>`. Supplying
`8.8.8.8; cat /etc/passwd` or `8.8.8.8 && whoami` chains an extra command.

Key metacharacters: `;`  `&&`  `||`  `|`  `` ` ``  `$( )`  newline.

## Detection logic

The WAF inspects inputs for shell metacharacters combined with common command
names in contexts that shouldn't contain them:
- Chaining/separator characters: `;`, `&&`, `|`, backticks, `$(`.
- Common commands: `cat`, `whoami`, `id`, `curl`, `wget`, `nc`, `/bin/sh`,
  `powershell`.
- Encoded variants — normalise before matching.

Because these characters are individually common, anomaly scoring and context
(which parameter, does the combination look like a command) matter more here than
almost anywhere else, to avoid false positives.

## Blocking approach

- Enable the managed RCE/command-injection rule group; detection-first, then
  block.
- Treat any endpoint that shells out as high-risk and monitor it closely.

## Tuning / testing notes

**False positives:** free-text fields where users legitimately type `&`, `|`, or
words like `id` or `curl`. A message "ping me & I'll reply" contains `&`. Scope
exceptions to genuine free-text parameters; keep strict blocking on parameters
that feed system commands.

**Testing (lab):**
- Confirm `8.8.8.8; cat /etc/passwd` and `127.0.0.1 && whoami` are blocked/logged.
- Confirm benign input with an ampersand in prose is not blocked in a free-text
  field.

## Real-world limitation

The durable fix is architectural: **don't pass user input to a shell.** Use
language-native APIs, parameterised process execution with argument arrays (no
shell interpolation), strict allow-listing of expected values, and least
privilege. The WAF is a strong mitigating layer in front of that — not a
substitute for it.
