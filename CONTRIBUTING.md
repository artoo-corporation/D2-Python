# Contributing to D2 (Python SDK)

Thank you for your interest in contributing!

This project is source-available under the Business Source License 1.1 (BSL 1.1). See LICENSE for terms, including the Change Date and Change License.

## Developer Certificate of Origin (DCO)

By contributing, you agree to the Developer Certificate of Origin (DCO) 1.1:

```
Developer Certificate of Origin
Version 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I have the right to submit it under the open source license indicated in the file; or
(b) The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate open source license and I have the right under that license to submit that work with modifications, whether created in whole or in part by me, under the same license (unless I am permitted to submit under a different license), as indicated in the file; or
(c) The contribution was provided directly to me by some other person who certified (a), (b) or (c) and I have not modified it.
(d) I understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information I submit with it, including my sign-off) is maintained indefinitely and may be redistributed consistent with this project or the open source license(s) involved.
```

To sign off your commits:

```
git commit -s -m "Your change summary"
```

This adds a Signed-off-by trailer using your git config name/email.

## Code of Conduct

Be respectful and inclusive; follow generally accepted standards of professional conduct.

## Development

- Fork and create feature branches
- Add tests and run `pytest`
- Ensure `python scripts/license_guard.py` and `python scripts/generate_notice.py` pass
- Open a pull request and ensure CI passes
