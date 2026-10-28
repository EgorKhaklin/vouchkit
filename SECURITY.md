# Security policy

vouchkit verifies identity presentations, so a flaw in it can let a relying party accept
something it should reject. Reports are welcome and taken seriously.

## Supported versions

vouchkit is pre-alpha. Only the latest release on PyPI and the `main` branch receive fixes.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private reporting instead: the **Security** tab of
this repository, then **Report a vulnerability**. The report stays private between you and
the maintainers until a fix is published.

Please include the affected version or commit, a description of the issue, and a minimal
reproduction if you have one (a crafted presentation, a test case, or the request and
response involved). Never include real personal data or real wallet credentials; synthetic
test material is enough.

## What to expect

- Acknowledgement within 14 days.
- An assessment and, where the report is confirmed, a fix plan shared with you.
- A fix released, and a GitHub security advisory published, within 60 days of
  confirmation for issues of medium severity or above. Reporters are credited unless they
  ask not to be.

vouchkit has one maintainer today, so these are the times we commit to rather than faster
ones we might miss.
