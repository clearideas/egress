"""``python -m clearideas_egress [auth] ...``

Without a subcommand this is the external ACL helper (``clearideas-egress-acl``).
``auth`` runs the Basic-auth token helper (``clearideas-egress-auth``). Dispatching
here avoids running an already-imported submodule with ``-m``.
"""

import sys

if sys.argv[1:2] == ["auth"]:
    from .auth import main as auth_main

    raise SystemExit(auth_main(sys.argv[2:]))

if sys.argv[1:2] == ["monitor"]:
    from .monitor import main as monitor_main

    raise SystemExit(monitor_main(sys.argv[2:]))

from .cli import main

raise SystemExit(main())
