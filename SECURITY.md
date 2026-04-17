# Security policy

## Supported versions

NexusHub is under active development. Security fixes target the latest minor release on the `main` branch.

| Version | Supported |
| ------- | --------- |
| 2.x     | Yes       |
| 1.x     | No (legacy bash installer; end-of-life) |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report vulnerabilities privately to: **security@tomeksdev.com**

If you prefer encrypted communication, use the PGP key below.

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
(PGP key placeholder — replace with the real public key before publishing.)
-----END PGP PUBLIC KEY BLOCK-----
```

### What to include

- A description of the issue and the impact.
- Steps to reproduce (PoC code, request payloads, configuration) so we can verify quickly.
- The affected component, commit hash or version, and environment.
- Your name/handle for credit (optional).

### Our commitment

- We will acknowledge your report within **72 hours**.
- We will provide an initial assessment and expected timeline within **7 days**.
- We will keep you informed as we investigate and fix.
- We will credit you in the release notes once the fix is public, unless you prefer to remain anonymous.

## Scope

In scope:

- **Backend API** (`backend/`) — authentication, authorization, input validation, session handling, rate limiting.
- **Authentication & JWT handling** — token issuance, rotation, revocation, secret management.
- **WireGuard key management** — private key storage, rotation, peer configuration integrity.
- **eBPF programs** (`ebpf/`) — memory safety, verifier bypasses, privilege escalation paths, map tampering.
- **CLI** (`cli/`) — command injection, privilege handling, config file parsing.
- **Container image** (`docker/Dockerfile`) — known-CVE base images, capability leaks, exposed secrets.

Out of scope:

- Social engineering, physical attacks.
- DoS via brute force against unthrottled endpoints (please report once you have a clearer vector).
- Vulnerabilities in third-party dependencies that have no practical impact in our use.
- Issues only reproducible on heavily modified forks.

## Safe harbor

We consider good-faith security research authorized under this policy and will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and service disruption.
- Do not exfiltrate more data than necessary to demonstrate the issue.
- Report promptly and give us reasonable time to remediate before any public disclosure.
