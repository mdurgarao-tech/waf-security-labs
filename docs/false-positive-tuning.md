# WAF false-positive tuning

A short process for handling a legitimate request that a WAF rule blocks. This is a general method, not a record of a specific case.

## Steps

1. **Detect.** An application team reports a blocked request, or a rule shows unusually many blocks on one URI.
2. **Find the event.** Match the request to the WAF event by time, source, URI and method.
3. **Identify the rule** and the part of the request that triggered it.
4. **Investigate.** Decide whether the request is a genuine attack or normal application behaviour.
5. **Scope the exception.** Limit it to the application, the URI and the specific parameter or condition. Avoid global exceptions.
6. **Test.** Confirm the legitimate request now works and that the same rule still blocks a real attack pattern.
7. **Monitor.** Watch events for the rule after the change.

## What I avoid

- Turning off a whole rule because one request was blocked.
- Adding exceptions that apply to every application.
- Changing a rule without understanding why it fired.

## Related

The [WAF log analyzer](../waf_log_analyzer.py) in this repo gives a first-pass summary of which rules, sources and URIs are being blocked.
