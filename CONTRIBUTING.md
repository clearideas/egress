# Contributing

Open an issue to discuss significant behavior changes. For a pull request, include the security boundary affected, tests for allowed and denied cases, and documentation updates. Run `make test` before submitting. It runs the unit tests, the end-to-end suite (in a bubblewrap sandbox, or in a container built from the image), and the image smoke test when Docker is available. See README, "Development and testing". Changes to the Dockerfile or entrypoint should also pass `make test-docker`.

Security-relevant changes should add an end-to-end test that fails on the previous code and asserts on evidence (DNS queries, origin connections, logs), not only on status codes.

Do not include production policies, credentials, customer data, or private infrastructure details. Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
