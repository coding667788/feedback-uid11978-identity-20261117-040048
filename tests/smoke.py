"""Quick smoke run: start a cluster, login, logout, verify."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.harness import Cluster

def main() -> int:
    cluster = Cluster(rp_count=2)
    try:
        cluster.start()
        print("cluster at", cluster.dir)
        t = cluster.ticket(iss=cluster.ISS_A, sub="alice")
        print("ticket claims", t["claims"])
        st, body = cluster.login(t["ticket"])
        print("login", st, {k: body.get(k) for k in ("session_id", "state", "sid", "generation")})
        sid = body.get("session_id")
        st, body = cluster.check(sid)
        print("check", st, body.get("reason"))
        ev = cluster.logout_event(
            event_id="e1", kind="sid", target_iss=cluster.ISS_A, sub="alice", sid=t["claims"]["sid"]
        )
        st, body = cluster.send_logout(ev["logout"])
        print("logout", st, body)
        st, body = cluster.check(sid)
        print("check after", st, body.get("reason"))
        print("usable", cluster.usable())
        return 0
    finally:
        cluster.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
