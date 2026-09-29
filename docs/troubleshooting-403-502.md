# Troubleshooting 403 and 502 through CDN, WAF and origin

This is the method I use. It is a general approach, not a description of one specific incident. I used it while investigating 403 and 502 responses during a CDN migration (see [cdn-migration.md](cdn-migration.md)).

## Request path

User, then CDN, then WAF, then origin (load balancer), then application. The first question is always which layer produced the response.

## 403 Forbidden

1. **Find who sent it.** Check the response headers and the CDN or WAF logs for the same timestamp, URI and method.
2. **If the WAF blocked it,** find the rule that fired and which part of the request triggered it: the URI, a parameter, a header or the body.
3. **Decide if it is an attack.** Compare the request with what the application legitimately sends.
4. **If it is a false positive,** add a narrow exception. Scope it to the application, URI or parameter. Do not turn off the whole rule.
5. **Retest,** then keep watching the events for the same rule.
6. **If the WAF allowed the request,** the 403 came from further along. Check the load balancer and application logs.

## 502 Bad Gateway

A 502 usually means the CDN could not get a valid response from the origin. I do not treat it as a WAF block at first.

1. **DNS.** Does the origin name resolve to the right address from the CDN side?
2. **Connectivity.** Is the origin reachable, and does its firewall allow the CDN's addresses?
3. **TLS.** Does the handshake succeed? Check the certificate, the hostname the CDN sends (SNI) and the protocol versions on both sides.
4. **Origin health.** Is the origin up, and is it timing out or resetting connections?
5. **If the CDN reached the origin and got an error back,** the problem is in the load balancer or the application, not the CDN.

Platforms name origin errors differently. CloudFront uses 502, 503 and 504. Cloudflare uses its own 52x codes. Read the platform's documentation for the exact meaning.
