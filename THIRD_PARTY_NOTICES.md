# Third-party notices

The Python library has no runtime dependencies outside the Python standard library. The optional Docker image installs Python, Squid, Apache HTTP Server utilities (`htpasswd`), OpenSSL and tini from Alpine packages. These components keep their own licenses and are not relicensed by this repository's MIT license. Check the installed package versions and licenses before distributing a container image.

The end-to-end test suite downloads Ubuntu packages (Squid, haproxy, nftables, iproute2, Apache HTTP Server utilities and their libraries; see `tests/e2e/toolchain.lock`) into a local cache for testing only. They are not redistributed by this repository.
