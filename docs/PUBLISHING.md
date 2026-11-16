# Publishing the Python package

The Python distribution is named `clearideas-egress`. GitHub releases contain
the wheel and source distribution built by CI. The `Publish to PyPI` workflow
uploads those exact assets after checking their package name and version.

## One-time PyPI setup

1. Sign in to [PyPI](https://pypi.org/) with an account that has a verified email
   address and two-factor authentication.
2. Under **Your account → Publishing**, add a **pending GitHub Actions trusted
   publisher** with these exact values:

   | Field | Value |
   | --- | --- |
   | PyPI project name | `clearideas-egress` |
   | GitHub owner | `clearideas` |
   | GitHub repository | `egress` |
   | Workflow filename | `publish-pypi.yml` |
   | Environment name | `pypi` |

   If the project already exists under the intended PyPI account, add the same
   trusted publisher under that project's **Publishing** settings instead.
   A pending publisher does not reserve the name until the first upload.

The GitHub `pypi` environment allows only `main` and `v*` refs. The publishing
job has `id-token: write` permission and uses PyPA's official publishing action;
no long-lived PyPI API token is stored in GitHub.

## First upload: v0.3.0

The `v0.3.0` GitHub release predates the publishing workflow. Once the pending
publisher is registered and this workflow is merged to `main`, run **Actions →
Publish to PyPI → Run workflow** on `main` with tag `v0.3.0`. The workflow
downloads the two existing release assets, verifies their metadata, and uploads
them to PyPI. Confirm the project page lists both files, then install in a clean
environment with `python -m pip install clearideas-egress==0.3.0`.

## Later releases

Publish a GitHub release only after its CI run passes and both distribution
assets are attached. The `release: published` event runs the same workflow for
the release tag. PyPI does not permit replacing an uploaded distribution file;
publish a new version if a release needs a correction.
