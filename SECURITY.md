# Security policy

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private reporting:
**Security > Report a vulnerability** on this repository
(https://github.com/seattlespicybite/grc-pal/security/advisories/new).

Include what you found, how to reproduce it, the version or image tag, and the impact you expect.
You will get an acknowledgment within 5 business days. Fixes for confirmed issues are released as
soon as practical, with credit if you want it.

## Supported versions

The latest minor release receives security fixes. Pin a version in production and watch this
repository's releases and advisories.

## Scope

In scope: the GRC-pal code, container image, Bicep template and deployment script.
Out of scope: your own deployment's configuration, Azure or GitHub platform issues (report those
to Microsoft or GitHub), and findings that need an already-compromised admin account.

Please test only against your own instance, never against someone else's.

The design and built-in protections are described in [docs/security.md](docs/security.md).
