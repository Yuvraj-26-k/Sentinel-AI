# Security policy

Sentinel-AI is a learning and defensive investigation tool. Port exposure,
service banners and AI-generated guidance do not establish a vulnerability.
Keep software updated and corroborate results with the system owner.

## Reporting a vulnerability

Please do not disclose secrets or exploitable security defects in a public
issue. Contact the maintainer at **ys9517711034@gmail.com** with a description,
affected commit/version and a minimal reproduction using a local test system.
Do not include credentials, personal information or third-party scan results.
This is a community project; no response-time or remediation SLA is promised.

## Scan data and AI

Scanning is local unless `--ai` is explicitly selected. That option sends the
documented report fields to the configured Gemini API. Review the README before
using it with private systems. Model output and remote service banners are
untrusted; never execute instructions found in either.
