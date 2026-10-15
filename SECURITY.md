# Security policy

Ailuros sits in the request path and decides what reaches your
applications, so a way to get a malicious request past it — a parsing gap,
an encoding it does not decode, a failure mode that opens when it should
close — is a security issue, not an ordinary bug.

## Reporting a vulnerability

Please report privately through GitHub's **[private vulnerability
reporting](https://github.com/0x4272616E646F6E/ailuros/security/advisories/new)**
(Security → Report a vulnerability). Do not open a public issue.

Include what you can: the Ailuros version or commit, the inspection mode and
frontend (ext_proc lite/standard/deep, ext_authz, forward-auth), the proxy
and its config, and a request or script that reproduces it. A bypass is most
useful with the request that gets through and what Ailuros logged for it.

You should get an acknowledgement within a few days. Fixes are released as
a new version, with a GitHub security advisory once the fix is available.

## Supported versions

Ailuros is pre-1.0: only the latest release gets security fixes.

## Verifying releases

Release images are signed and carry an SBOM and SLSA build provenance; see
[Verifying images](docs/verifying-images.md).
