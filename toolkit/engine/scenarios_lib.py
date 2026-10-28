"""Ready-made SCENARIOS for qa-spec.py. Each builder returns {"name", "run"} for the scenario engine.

  from scenarios_lib import state_machine, stale_session, reuse_after_logout, double_submit

state_machine(name, states, allowed, reach, get_state, transition, role)
    Product rule "only these status transitions are legal". For every pair (from, to) that is NOT in `allowed`, bring a fresh
    object to `from` (reach(api, ctx, state) -> object ref, or None if unreachable), try to move it to `to` as `role`
    (transition(api, role, ref, to) -> Resp), and fail when a 2xx is returned or get_state(api, ref) changed.
    Catches: reopening closed things, skipping payment, cancelling shipped orders, double-refund preconditions.

stale_session(name, login, protected, revoke)
    login(api) -> headers, protected(api, headers) -> Resp (must be 2xx before), revoke(api, ctx) performs the admin action
    (delete/block/demote user, change password). Afterwards the OLD token must be rejected (401/403). Catches JWTs that keep
    working after the account is blocked, deleted or demoted (a classic NextAuth / JWT bug: role copied into the token at login).

reuse_after_logout(name, login, logout, protected)
    Token must stop working after logout.

double_submit(name, make_request, count, role, n=2)
    Send the same create request n times back to back; count(api, ctx) -> number of rows that exist for it. Fails when n
    rows were created for what the product treats as one action (double click, retry): pair with an idempotency key rule.
"""
import itertools


def state_machine(name, states, allowed, reach, get_state, transition, role):
    def run(api, ctx):
        bad = []
        for frm, to in itertools.permutations(states, 2):
            if (frm, to) in allowed:
                continue
            ref = reach(api, ctx, frm)
            if ref is None:
                continue
            resp = transition(api, role, ref, to)
            now = get_state(api, ref)
            if resp.ok and now == to:
                bad.append(f"{frm} -> {to}")
            elif resp.status >= 500:
                bad.append(f"{frm} -> {to} (5xx)")
        return f"illegal transitions accepted: {', '.join(bad)}" if bad else None
    return {"name": name, "run": run}


def stale_session(name, login, protected, revoke):
    def run(api, ctx):
        headers = login(api)
        before = protected(api, headers)
        if not before.ok:
            return None                                  # cannot establish the precondition: not a finding
        revoke(api, ctx)
        after = protected(api, headers)
        if after.ok:
            return f"old session still works after the account was revoked ({after.status})"
    return {"name": name, "run": run}


def reuse_after_logout(name, login, logout, protected):
    def run(api, ctx):
        headers = login(api)
        if not protected(api, headers).ok:
            return None
        logout(api, headers)
        after = protected(api, headers)
        if after.ok:
            return f"token still accepted after logout ({after.status})"
    return {"name": name, "run": run}


def double_submit(name, make_request, count, role, n=2):
    def run(api, ctx):
        before = count(api, ctx)
        req = make_request(api, ctx)
        for _ in range(n):
            api.call(role, req["method"], req["path"], req.get("body"))
        made = count(api, ctx) - before
        if made >= n:
            return f"{n} identical submits created {made} rows (no idempotency / duplicate guard)"
    return {"name": name, "run": run}
