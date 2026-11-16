# Publishing the Python package

The Python distribution is named `clearideas-egress`. GitHub releases contain
the wheel and source distribution built by CI. The `Publish to PyPI` workflow
uploads those exact assets after checking their package name and version.

## Trusted publisher

The `clearideas` PyPI account has an active GitHub Actions trusted publisher:

| Field | Value |
| --- | --- |
| PyPI project name | `clearideas-egress` |
| GitHub owner | `clearideas` |
| GitHub repository | `egress` |
| Workflow filename | `publish-pypi.yml` |
| Environment name | `pypi` |

Manage it under the [project's PyPI publishing settings](https://pypi.org/manage/project/clearideas-egress/settings/publishing/).

The GitHub `pypi` environment allows only `main` and `v*` refs. The publishing
job has `id-token: write` permission and uses PyPA's official publishing action;
no long-lived PyPI API token is stored in GitHub.

## Existing GitHub releases

Version `0.3.0` was published to [PyPI](https://pypi.org/project/clearideas-egress/0.3.0/)
on 2026-11-16. It was uploaded manually through the workflow because its GitHub
release predates the publishing workflow.

For a different existing GitHub release that has **not** been uploaded to PyPI,
run **Actions → Publish to PyPI → Run workflow** on `main` with that release tag.
The workflow downloads and verifies the release's wheel and source distribution
before uploading them. Do not rerun it for an already published version.

## Later releases

Publish a GitHub release only after its CI run passes and both distribution
assets are attached. The `release: published` event runs the same workflow for
the release tag. PyPI does not permit replacing an uploaded distribution file;
publish a new version if a release needs a correction.
