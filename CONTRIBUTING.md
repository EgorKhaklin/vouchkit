# Contributing to vouchkit

Thanks for your interest. vouchkit is trust infrastructure: small, auditable, adversarially
tested. Contributions should keep it that way.

## License and Developer Certificate of Origin (DCO)

vouchkit is licensed under the [Apache License 2.0](LICENSE). By contributing, you agree your
contributions are licensed under the same terms. We use the
[Developer Certificate of Origin](https://developercertificate.org/) instead of a CLA — sign
off every commit:

```
git commit -s -m "feat: ..."
```

Use your real name and a reachable email. Pull requests with unsigned commits cannot merge.

## Ground rules

- **No personal data, ever, in logs or errors.** Verification failures name the *rule* that
  failed, never claim values.
- **Adversarial tests first.** A change to verification logic ships with the forgery/misuse
  cases it newly rejects (or proves still rejected).
- **Small dependency tree.** New runtime dependencies need a maintainer discussion before the
  PR; `cryptography` is currently the only one, deliberately.
- **Scope discipline.** We implement what the EUDI ARF/HAIP profile mandates for relying
  parties. Speculative protocol surface is a discussion, not a PR.
- `main` is always releasable: feature branch + pull request, CI green.

## Workflow

1. Open or comment on an issue before large changes.
2. Branch, implement, `uv run pytest` green, commit with `-s`.
3. PRs describe: what, why, how tested, and any security consideration.

## Reporting security issues

Do not open public issues for vulnerabilities. Report them privately as described in
[SECURITY.md](SECURITY.md).
