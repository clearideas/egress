"""One-line-in, one-line-out Squid external ACL helper."""

from __future__ import annotations

import os
import sys

from .policy import HTTPPolicy, authorize, load_file_policy, parse_acl_line


def main() -> int:
    file_path = os.environ.get("EGRESS_POLICY_FILE")
    url = os.environ.get("EGRESS_POLICY_URL")
    try:
        if bool(file_path) == bool(url):
            raise ValueError("set exactly one of EGRESS_POLICY_FILE or EGRESS_POLICY_URL")
        backend = load_file_policy(file_path) if file_path else HTTPPolicy(
            url, token=os.environ.get("EGRESS_POLICY_TOKEN")
        )
    except (OSError, ValueError) as error:
        print(f"egress ACL startup failed: {error}", file=sys.stderr)
        return 1

    for line in sys.stdin:
        request = parse_acl_line(line)
        print("OK" if authorize(request, backend) else "ERR", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
