# CDN migration: Akamai to Cloudflare and AWS CloudFront

This note describes my part in a production CDN migration programme at a previous employer. It is written at process level. It has no customer names, hostnames, ticket numbers or traffic figures.

## My role

I worked on the security and traffic-path side: WAF policy, DNS, TLS, origin connectivity and validation. The programme covered migrations from Akamai to Cloudflare and from Akamai to AWS CloudFront.

## Phases

1. **Discovery and inventory.** Listed the applications in scope before any change was made.
2. **Target configuration.** TLS/SSL certificates (ACM on the AWS side), origin settings and cache behaviour on the new platform.
3. **WAF policy mapping.** Mapped the existing Akamai security policy to the target platform's WAF.
4. **Lower-environment testing.** Tested in a lower environment before production traffic was moved.
5. **Cutover.** DNS/CNAME change, with the TTL reduced beforehand and a rollback path to Akamai kept ready.
6. **Post-cutover validation.** Checked cache hit and miss behaviour, TLS versions, HTTP response codes and WAF events.
7. **Troubleshooting.** Investigated 403 and 502 responses during the migration. The method is in [troubleshooting-403-502.md](troubleshooting-403-502.md).
8. **Rollback.** Rollback to Akamai was validated when it was required.
9. **Documentation.** Wrote up migration findings and implementation details.

## Not covered here

Application counts, traffic volumes and timelines are not in this note. I only state numbers I can defend.
