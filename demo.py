"""Live demo over real HTTP: 4 RP processes, out-of-order logouts, crash points.

Prints every request/response verdict.  Exits non-zero if any assertion fails.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tests.harness import Cluster

STEP = 0


def say(message: str) -> None:
    global STEP
    STEP += 1
    print(f"\n[{STEP:02d}] {message}")


def show(label: str, status: int, body, keys=None) -> None:
    if isinstance(body, dict) and keys:
        body = {k: body.get(k) for k in keys if k in body}
    print(f"     {label:<34} HTTP {status}  {body}")


def main() -> int:
    cluster = Cluster(rp_count=4)
    failures: list[str] = []

    def expect(condition: bool, message: str) -> None:
        if condition:
            print(f"     OK   {message}")
        else:
            print(f"     FAIL {message}")
            failures.append(message)

    try:
        say("启动 IdP 与 4 个独立 RP 进程（共享一个 SQLite）")
        cluster.start()
        for rp in cluster.rps:
            print(f"     {rp.name}  {rp.url}  pid={rp.proc.pid}")
        print(f"     IdP    {cluster.idp.url}  pid={cluster.idp.proc.pid}")
        print(f"     DB     {cluster.db_path}")

        say("登录：alice@alpha 两代 + alice@beta 一代 + 同 sid 文本")
        a1 = cluster.ticket(iss=cluster.ISS_A, sub="alice")["ticket"]
        sa1 = cluster.login(a1, cluster.rp(0))[1]
        show("login alpha alice gen1", 200, sa1, ("sid", "generation", "state"))
        a2 = cluster.ticket(iss=cluster.ISS_A, sub="alice")["ticket"]
        sa2 = cluster.login(a2, cluster.rp(1))[1]
        show("login alpha alice gen2", 200, sa2, ("sid", "generation", "state"))
        b1 = cluster.ticket(iss=cluster.ISS_B, sub="alice", sid="shared-text")["ticket"]
        sb1 = cluster.login(b1, cluster.rp(2))[1]
        show("login beta  alice gen1", 200, sb1, ("sid", "generation", "state"))

        say("同一票据重试：必须返回同一会话")
        retry = cluster.login(a1, cluster.rp(3))
        show("retry gen1 ticket", retry[0], retry[1], ("session_id", "idempotent", "state"))
        expect(retry[1]["session_id"] == sa1["session_id"], "same session_id returned")

        say("缓存预热：4 个进程各鉴权两次")
        for rp in cluster.rps:
            cluster.check(sa1["session_id"], rp)
            status, body = cluster.check(sa1["session_id"], rp)
            expect(status == 200 and body.get("cache") == "hit", f"{rp.name} cache hit")

        say("关键场景：旧登出（cutoff=1）晚于新登录（gen2）到达")
        ev_old = cluster.logout_event(
            event_id="demo-old", kind="range", target_iss=cluster.ISS_A, sub="alice", cutoff=1
        )
        status, body = cluster.send_logout(ev_old["logout"], cluster.rp(2))
        show("range logout cutoff=1", status, body, ("status", "watermark", "epoch"))
        for rp in cluster.rps:
            st_old, _ = cluster.check(sa1["session_id"], rp)
            st_new, _ = cluster.check(sa2["session_id"], rp)
            expect(st_old == 401, f"{rp.name}: gen1 rejected")
            expect(st_new == 200, f"{rp.name}: gen2 still allowed")

        say("重复投递同一通知：幂等，不推进 epoch")
        epoch_before = cluster.admin_state()["epoch"]
        status, body = cluster.send_logout(ev_old["logout"], cluster.rp(0))
        show("duplicate logout", status, body, ("status", "epoch"))
        expect(body["status"] == "duplicate", "status == duplicate")
        expect(cluster.admin_state()["epoch"] == epoch_before, "epoch unchanged")

        say("同 event_id 不同内容：必须冲突且不施加")
        ev_conflict = cluster.logout_event(
            event_id="demo-old", kind="sid", target_iss=cluster.ISS_A, sub="alice",
            sid=sa2["sid"],
        )
        status, body = cluster.send_logout(ev_conflict["logout"], cluster.rp(1))
        show("conflicting body", status, body, ("error", "detail"))
        expect(status == 409 and body["error"] == "event_conflict", "409 event_conflict")
        expect(cluster.check(sa2["session_id"])[0] == 200, "gen2 not killed by conflict")

        say("单 sid 登出 vs 不同 issuer 同 sid 文本")
        ev_sid = cluster.logout_event(
            event_id="demo-sid", kind="sid", target_iss=cluster.ISS_B, sub="alice",
            sid="shared-text", event_iss=cluster.LOGOUT_B,
        )
        status, body = cluster.send_logout(ev_sid["logout"], cluster.rp(3))
        show("sid logout beta/shared-text", status, body, ("status", "sid_recorded"))
        expect(cluster.check(sb1["session_id"])[0] == 401, "beta session rejected")
        expect(cluster.check(sa2["session_id"])[0] == 200, "alpha session untouched")

        say("范围登出 cutoff=2：迟到的更低通知不得降低水位")
        ev_hi = cluster.logout_event(
            event_id="demo-hi", kind="range", target_iss=cluster.ISS_A, sub="alice", cutoff=2
        )
        cluster.send_logout(ev_hi["logout"], cluster.rp(0))
        ev_lo = cluster.logout_event(
            event_id="demo-lo", kind="range", target_iss=cluster.ISS_A, sub="alice", cutoff=0
        )
        status, body = cluster.send_logout(ev_lo["logout"], cluster.rp(1))
        show("late cutoff=0", status, body, ("status", "watermark"))
        expect(body["watermark"] == 2, "watermark stayed at 2")
        expect(cluster.usable() == set(), "no usable sessions left")

        say("崩溃点 1：去重记录已写、撤销未完成 → 真实 os._exit")
        c1 = cluster.ticket(iss=cluster.ISS_A, sub="bob")["ticket"]
        s_c1 = cluster.login(c1, cluster.rp(0))[1]
        ev_c1 = cluster.logout_event(
            event_id="demo-crash1", kind="sid", target_iss=cluster.ISS_A,
            sub="bob", sid=s_c1["sid"],
        )
        victim = cluster.rp(0)
        cluster.hook("logout.after_dedup", port=victim.port, mode="die")
        try:
            cluster.send_logout(ev_c1["logout"], victim)
        except Exception:
            pass
        cluster.wait_until(lambda: not victim.alive(), timeout=20)
        print(f"     {victim.name} died with rc={victim.proc.returncode}")
        state = cluster.admin_state(rp=cluster.rp(1))
        pending = [e for e in state["events"] if e["event_id"] == "demo-crash1"]
        show("dedup row after crash", 200, pending[0] if pending else None,
             ("event_id", "applied"))
        expect(bool(pending) and pending[0]["applied"] == 0,
               "dedup recorded, revocation not applied, no response sent")
        restarted = cluster.restart_rp(victim)
        print(f"     restarted as {restarted.name} {restarted.url}")
        status, body = cluster.send_logout(ev_c1["logout"], restarted)
        show("redelivery", status, body, ("status",))
        expect(body["status"] == "applied", "redelivery completed revocation")
        expect(cluster.check(s_c1["session_id"], restarted)[0] == 401, "bob rejected")

        say("崩溃点 2：撤销已提交、响应未发出 → 真实 os._exit")
        c2 = cluster.ticket(iss=cluster.ISS_B, sub="bob")["ticket"]
        s_c2 = cluster.login(c2, cluster.rp(1))[1]
        ev_c2 = cluster.logout_event(
            event_id="demo-crash2", kind="sid", target_iss=cluster.ISS_B,
            sub="bob", sid=s_c2["sid"], event_iss=cluster.LOGOUT_B,
        )
        victim2 = cluster.rp(2)
        cluster.hook("logout.after_commit", port=victim2.port, mode="die")
        try:
            cluster.send_logout(ev_c2["logout"], victim2)
        except Exception:
            pass
        cluster.wait_until(lambda: not victim2.alive(), timeout=20)
        print(f"     {victim2.name} died with rc={victim2.proc.returncode}")
        for rp in cluster.rps:
            if rp.alive():
                expect(cluster.check(s_c2["session_id"], rp)[0] == 401,
                       f"{rp.name}: bob@beta revoked despite no response")
        restarted2 = cluster.restart_rp(victim2)
        status, body = cluster.send_logout(ev_c2["logout"], restarted2)
        show("redelivery", status, body, ("status",))
        expect(body["status"] == "duplicate", "redelivery is a duplicate")

        say("最终状态")
        summary = cluster.admin_state()
        print(f"     epoch        = {summary['epoch']}")
        print(f"     watermarks   = {[(s['iss'].split('//')[-1], s['sub'], s['cutoff_generation']) for s in summary['subjects']]}")
        print(f"     killed sids  = {[(k['iss'].split('//')[-1], k['sid']) for k in summary['sid_revocations']]}")
        print(f"     seen events  = {[(e['event_id'], e['applied']) for e in summary['events']]}")
        print(f"     usable       = {sorted(cluster.usable())}")
        print(f"     counts       = {summary['counts']}")

        print("\n" + "=" * 70)
        if failures:
            print(f"DEMO FAILED — {len(failures)} assertion(s):")
            for failure in failures:
                print(f"  - {failure}")
            return 1
        print("DEMO PASSED — all assertions held")
        return 0
    finally:
        cluster.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
