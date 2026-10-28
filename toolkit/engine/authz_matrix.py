"""Authorization matrix: who can touch what, derived from OpenAPI + roles.

Checks (all candidates, to be proven by a PoC):
  BOLA/IDOR      resource created by OWNER role is readable/changeable by another user or anon
  MISSING-AUTH   endpoint (not in PUBLIC) answers 2xx to anon
  PRIV-ESC       admin-only endpoint answers 2xx to a plain user

Spec (qa-spec.py) knobs, all optional:
  PUBLIC      {"GET /products/", ...}   endpoints meant to be open to anon
  ADMIN_ONLY  {"POST /products/", ...}  extra admin-only endpoints (paths containing /admin are auto-added)
  OWNER       {"POST /orders/": "user_a"}  role that creates the resource (default user_a)
  BODIES      {"POST /orders/": {...}}  valid bodies where the schema example is not enough
  IDS         {"user_id": "<id of a throwaway user>"}   ids used when probing admin-only endpoints that take a path param
  SKIP        {"POST /auth/logout"}     endpoints never probed
  OWNED_IDS   {"/rest/basket": {"user_a": 3}}   ids that do not come from a POST creator (login response, seed data):
              collection path -> {owner role: id}; attackers are probed against that id
"""
import re

from api import WRITE_METHODS, endpoints, example, extract_id, fill, key, prefix_of
import trust

ATTACKERS = ("user_b", "anon")
LOGIC_STATUSES = (409, 410)     # business-rule answers (conflict / gone): nobody asks "may you?" with these, so the access check was passed or missing


CONFLICT_SIGNS = ("unique constraint", "integrityerror", "duplicate key", "duplicate entry", "already exists", "must be unique")


def is_repeat_write_conflict(resp) -> bool:
    """A create that failed because the value it carries already exists: a 409, or a 4xx/5xx whose body names a uniqueness
    violation (a raw DB IntegrityError leaking out as a 500 counts). The probe never got a resource to attack: setup failed."""
    if resp.ok:
        return False
    return resp.status == 409 or any(s in resp.text.lower() for s in CONFLICT_SIGNS)


def _compare_with_owner(api, owner, child, path, resp, own=None):
    """For a readable resource: does the attacker's 2xx carry the OWNER's data? -> (severity | None, text for the finding).
    Identical body = data exposed (high). A 2xx with a different body may be a generic or filtered answer (medium, verify).
    Writes and unreadable resources are left to the caller's rules (None)."""
    if child["method"] != "GET":
        return None, ""
    own = own or api.call(owner, "GET", path)
    if not own.ok:
        return None, ""
    if own.text == resp.text:
        return "high", " - body identical to the owner's: data exposed"
    return "medium", " - 2xx but the body differs from the owner's: verify it is not a generic or filtered answer"


def _write_readback(api, owner, child, path, write_body, write_resp):
    """After an attacker got 2xx on a write: did the write stick? -> (kind, severity, detail_suffix) or None.

    Confirmed when a GET (same path) as the owner shows the attacker's body fields, or the resource is gone after DELETE.
    If there is no GET sibling or the GET is inconclusive -> UNKNOWN-AUTH (medium): the 2xx alone is not proven access.
    """
    if child["method"] not in WRITE_METHODS or not write_resp.ok:
        return None
    get_path = path
    after = api.call(owner, "GET", get_path)
    parent = get_path.rsplit("/", 1)[0]
    if child["method"] != "DELETE" and after.status in (404, 405) and parent not in ("", "/"):
        # sub-action paths such as /orders/5/status are often not GET-able; the parent resource shows the field
        parent_after = api.call(owner, "GET", parent)
        if parent_after.ok:
            after = parent_after
    if child["method"] == "DELETE":
        if after.status in (404, 410):
            return ("BOLA/IDOR", "high", " - read-back: owner GET is gone after attacker DELETE (write stuck)")
        return ("UNKNOWN-AUTH", "medium",
                f" - attacker DELETE got {write_resp.status} but owner GET still {after.status}: write effect unconfirmed")
    if not after.ok:
        return ("UNKNOWN-AUTH", "medium",
                f" - attacker write got {write_resp.status} but owner cannot re-read ({after.status}): effect unconfirmed")
    if write_body and isinstance(write_body, dict) and isinstance(after.json, dict):
        matched = [k for k, v in write_body.items() if k in after.json and after.json.get(k) == v]
        if matched:
            return ("BOLA/IDOR", "high",
                    f" - read-back: owner GET reflects attacker's write fields {matched}")
    return ("UNKNOWN-AUTH", "medium",
            " - attacker write got 2xx; read-back did not prove the change stuck (verify manually)")


MEMBER_RE = re.compile(r"member|collaborator|participant|share|invite", re.I)
ACCOUNT_RE = re.compile(r"(^|/)(me|self|whoami|account|profile|current[-_]?user)$", re.I)
OWNER_WORDS = re.compile(r"\bowners?\b|\badmin|\bmanagers?\b|maintainer", re.I)
LOW_ROLE_RE = re.compile(r"member|viewer|reader|guest|user|read", re.I)


def _account_id(api, role, eps):
    for e in eps:
        if e["method"] == "GET" and not e["path_params"] and ACCOUNT_RE.search(e["path"].rstrip("/")):
            r = api.call(role, "GET", e["path"])
            if r.ok and isinstance(r.json, dict) and isinstance(r.json.get("id"), (int, str)):
                return r.json["id"]
    return None


def _member_write(api, eps, spec_doc, qa, owner, rid, collection, skip, add, notes):
    """The owner adds another ordinary role as a plain member of a fresh resource; the member then tries the operations that change
    the resource itself (PATCH/PUT /x/{id}). A 2xx means members can change settings: medium when the operation's own text says
    owners/admins only, low ('confirm the role matrix') when the document is silent, since many products let members edit."""
    members = next((e for e in eps if e["method"] == "POST" and e["path"].startswith(collection + "/") and len(e["path_params"]) == 1
                    and MEMBER_RE.search(e["path"].rstrip("/").rsplit("/", 1)[-1]) and key(e) not in skip), None)
    if members is None:
        return
    param = members["path_params"][0]
    updates = [e for e in eps if e["method"] in ("PATCH", "PUT") and e["path"] == f"{collection}/{{{param}}}" and key(e) not in skip]
    member = next((r for r in api.roles if r not in ("anon", owner)), None)
    if not updates or member is None:
        return
    uid = _account_id(api, member, eps)
    if uid is None:
        notes.append(f"{key(members)}: member write not tested, no GET /me-like endpoint to learn {member}'s id")
        return
    body = example(members["body_schema"], spec_doc) if members["body_schema"] is not None else {}
    body = dict(body) if isinstance(body, dict) else {}
    props = (members["body_schema"] or {}).get("properties", {}) if isinstance(members["body_schema"], dict) else {}
    for name, sch in props.items():
        low = name.lower()
        enum = sch.get("enum") if isinstance(sch, dict) else None
        if low.endswith("id") and re.search(r"user|member|account|customer|person", low):
            body[name] = uid
        elif enum and re.search(r"role|permission|level|access", low):
            body[name] = next((v for v in enum if isinstance(v, str) and LOW_ROLE_RE.search(v) and not OWNER_WORDS.search(v)), enum[-1])
    added = api.call(owner, "POST", fill(members["path"], {param: rid}), body)
    if not added.ok:
        notes.append(f"{key(members)}: could not add {member} as a member (status {added.status}); member write not tested")
        return
    for u in updates:
        path = fill(u["path"], {param: rid})
        ubody = _body(u, qa, spec_doc)
        if not api.call(owner, u["method"], path, ubody).ok:           # control: the owner can do it with this body
            continue
        resp = api.call(member, u["method"], path, ubody)
        if resp.ok:
            node = ((spec_doc.get("paths") or {}).get(u["path"]) or {}).get(u["method"].lower()) or {}
            text = f"{u.get('summary', '')} {node.get('description', '')}"
            documented = bool(OWNER_WORDS.search(text))
            add("AUTHZ-MEMBER-WRITE", "medium" if documented else "low", u, member, resp,
                f"{member}, added as a plain member, got {resp.status} on {key(u)}"
                + (": the operation says owners/admins only" if documented else "; the document does not say who may change it, confirm the role matrix"))


def _body(ep, qa, spec_doc):
    custom = getattr(qa, "BODIES", {}).get(key(ep))
    if custom is not None:
        return custom
    if ep["body_schema"] is not None and ep["method"] in WRITE_METHODS:
        return example(ep["body_schema"], spec_doc)
    return None


def inferred_public(spec_doc: dict, eps: list) -> set:
    """Operations the OpenAPI document itself declares as needing no credentials: an explicit empty `security: []` on the operation,
    or inherited from an explicit empty global `security: []`. Only trusted when the document really describes security somewhere
    (a global requirement or an operation with a requirement); a spec that never mentions security says nothing about who may call what,
    so nothing is inferred and every anonymous 2xx is still reported."""
    glob = spec_doc.get("security")
    ops = [(e, ((spec_doc.get("paths") or {}).get(e["path"]) or {}).get(e["method"].lower()) or {}) for e in eps]
    describes_security = bool(glob) or any(isinstance(o, dict) and o.get("security") for _, o in ops)
    if not describes_security:
        return set()
    out = set()
    for e, o in ops:
        effective = o.get("security") if isinstance(o, dict) and "security" in o else glob
        if effective is not None and len(effective) == 0:
            out.add(key(e))
    return out


def run(api, spec_doc, qa) -> dict:
    eps = endpoints(spec_doc)
    declared_public = set(getattr(qa, "PUBLIC", set()))
    inferred = inferred_public(spec_doc, eps) - declared_public
    public = declared_public | inferred
    skip = set(getattr(qa, "SKIP", set()))
    admin_only = set(getattr(qa, "ADMIN_ONLY", set())) | {key(e) for e in eps if "/admin" in e["path"]}
    owner_map = getattr(qa, "OWNER", {})
    findings, notes, setup_failed, probes = [], [], [], 0
    probed: set[str] = set()      # id-endpoints already attacked through a creator

    def add(kind, severity, ep, role, resp, detail):
        findings.append({"kind": kind, "severity": severity, "endpoint": key(ep), "role": role,
                         "status": resp.status, "detail": detail, "response": resp.text[:200]})

    creators = [e for e in eps if e["method"] == "POST" and not e["path_params"] and key(e) not in skip]
    for creator in creators:
        owner = owner_map.get(key(creator), "user_a")
        if owner not in api.roles:
            notes.append(f"{key(creator)}: owner role '{owner}' not configured, skipped")
            continue
        collection = creator["path"].rstrip("/")
        children = [e for e in eps if e["path"].startswith(collection + "/") and len(e["path_params"]) == 1
                    and prefix_of(e["path"], e["path_params"][0]) == collection and key(e) not in skip]
        if not children:
            continue
        body = _body(creator, qa, spec_doc)

        def make():
            r = api.call(owner, "POST", creator["path"], body)
            if is_repeat_write_conflict(r):
                setup_failed.append(f"{key(creator)}: repeated create as {owner} hit a uniqueness conflict (status {r.status}); "
                                    f"the probes behind it did not run. Give the unique field a fresh value per create")
            return extract_id(r.json) if r.ok else None

        first = api.call(owner, "POST", creator["path"], body)
        if is_repeat_write_conflict(first):
            setup_failed.append(f"{key(creator)}: first create as {owner} hit a uniqueness conflict (status {first.status}); "
                                f"the probes behind it did not run")
            continue
        if not first.ok or extract_id(first.json) is None:
            notes.append(f"{key(creator)}: could not create sample as {owner} (status {first.status}); "
                         f"add BODIES['{key(creator)}'] to qa-spec.py")
            continue
        try:
            _member_write(api, eps, spec_doc, qa, owner, extract_id(first.json), collection, skip, add, notes)
        except Exception as exc:          # an odd answer must not kill the matrix: note it (the status degrades)
            notes.append(f"{key(creator)}: member write check crashed: {type(exc).__name__}: {exc}"[:200])
        for attacker in ATTACKERS:        # each attacker owns a resource too: a membership check that only asks "member of SOME x?" is invisible otherwise
            if attacker != "anon" and attacker != owner and attacker in api.roles:
                api.call(attacker, "POST", creator["path"], body)
        for child in children:
            for attacker in ATTACKERS:
                if attacker not in api.roles or key(child) in public:
                    continue
                rid = make()
                if rid is None:
                    break
                probes += 1
                probed.add(key(child))
                path = fill(child["path"], {child["path_params"][0]: rid})
                wbody = _body(child, qa, spec_doc)
                resp = api.call(attacker, child["method"], path, wbody)
                if resp.ok:
                    if child["method"] in WRITE_METHODS:
                        rb = _write_readback(api, owner, child, path, wbody, resp)
                        if rb:
                            kind, sev, ev_text = rb
                            if attacker == "anon" and kind == "BOLA/IDOR":
                                kind = "MISSING-AUTH"
                            add(kind, sev, child, attacker, resp,
                                f"{attacker} got {resp.status} on {child['method']} {path}, resource created by {owner}{ev_text}")
                        else:
                            add("BOLA/IDOR" if attacker != "anon" else "MISSING-AUTH", "high", child, attacker, resp,
                                f"{attacker} got {resp.status} on {child['method']} {path}, resource created by {owner}")
                    else:
                        kind = "BOLA/IDOR" if attacker != "anon" else "MISSING-AUTH"
                        sev = "medium" if attacker != "anon" else "high"
                        ev_sev, ev_text = _compare_with_owner(api, owner, child, path, resp)
                        add(kind, ev_sev or sev, child, attacker, resp,
                            f"{attacker} got {resp.status} on {child['method']} {path}, resource created by {owner}{ev_text}")
                elif resp.status in LOGIC_STATUSES:
                    add("AUTHZ-REACHED-LOGIC", "medium", child, attacker, resp,
                        f"{attacker} got {resp.status} on {child['method']} {path} (resource created by {owner}): not 401/403/404, so the request got past any "
                        "access check and was stopped by a business rule. Not proven access: give qa-spec BODIES['" + key(child) + "'] a body that is valid in that state")

    # resources whose ids do not come from a POST creator (login response, seed data): OWNED_IDS = {"/rest/basket": {"user_a": 3}}
    for coll, owners in getattr(qa, "OWNED_IDS", {}).items():
        children = [e for e in eps if e["path"].startswith(coll + "/") and len(e["path_params"]) == 1
                    and prefix_of(e["path"], e["path_params"][0]) == coll and key(e) not in skip]
        for owner, rid in owners.items():
            for child in children:
                path = fill(child["path"], {child["path_params"][0]: rid})
                body = _body(child, qa, spec_doc)
                if child["method"] == "GET":
                    own = api.call(owner, "GET", path)
                    if not own.ok:
                        continue                                  # the owner cannot read it either: precondition missing, say nothing
                for attacker in ATTACKERS:
                    if attacker not in api.roles or attacker == owner or key(child) in public:
                        continue
                    probes += 1
                    probed.add(key(child))
                    wbody = body if child["method"] in WRITE_METHODS else None
                    resp = api.call(attacker, child["method"], path, wbody)
                    if resp.ok:
                        if child["method"] in WRITE_METHODS:
                            rb = _write_readback(api, owner, child, path, wbody, resp)
                            if rb:
                                kind, sev, ev_text = rb
                                if attacker == "anon" and kind == "BOLA/IDOR":
                                    kind = "MISSING-AUTH"
                                add(kind, sev, child, attacker, resp,
                                    f"{attacker} got {resp.status} on {child['method']} {path}, resource belongs to {owner} (OWNED_IDS){ev_text}")
                            else:
                                add("BOLA/IDOR" if attacker != "anon" else "MISSING-AUTH", "high", child, attacker, resp,
                                    f"{attacker} got {resp.status} on {child['method']} {path}, resource belongs to {owner} (OWNED_IDS)")
                        else:
                            kind = "BOLA/IDOR" if attacker != "anon" else "MISSING-AUTH"
                            ev_sev, ev_text = _compare_with_owner(api, owner, child, path, resp, own if child["method"] == "GET" else None)
                            add(kind, ev_sev or ("high" if attacker == "anon" else "medium"), child, attacker, resp,
                                f"{attacker} got {resp.status} on {child['method']} {path}, resource belongs to {owner} (OWNED_IDS){ev_text}")
                    elif resp.status in LOGIC_STATUSES:
                        add("AUTHZ-REACHED-LOGIC", "medium", child, attacker, resp,
                            f"{attacker} got {resp.status} on {child['method']} {path} (OWNED_IDS, belongs to {owner}): past the access check, stopped by a business rule")

    # admin-only endpoints that take an id (e.g. PATCH /users/{user_id}/role): need IDS = {"user_id": <a harmless id>}
    ids = getattr(qa, "IDS", {})
    for ep in eps:
        k = key(ep)
        if k in skip or k in probed or not ep["path_params"] or k not in admin_only or "user_a" not in api.roles:
            continue
        if not all(p in ids for p in ep["path_params"]):
            notes.append(f"{k}: admin-only but IDS lacks {ep['path_params']} in qa-spec.py, not probed")
            continue
        probes += 1
        resp = api.call("user_a", ep["method"], fill(ep["path"], ids), _body(ep, qa, spec_doc))
        if resp.ok:
            add("PRIV-ESC", "high", ep, "user_a", resp, f"plain user got {resp.status} on admin-only endpoint")

    # function-level checks on endpoints without a resource id
    for ep in eps:
        k = key(ep)
        if k in skip or ep["path_params"]:
            continue
        body = _body(ep, qa, spec_doc)
        if k not in public and "anon" in api.roles:
            probes += 1
            resp = api.call("anon", ep["method"], fill(ep["path"], {}), body, {n: "1" for n in ep["query_required"]} or None)
            if resp.ok:
                add("MISSING-AUTH", "high" if ep["method"] in WRITE_METHODS else "medium", ep, "anon", resp,
                    f"anon got {resp.status}; add to PUBLIC if intended")
            elif resp.status in LOGIC_STATUSES:
                add("AUTHZ-REACHED-LOGIC", "medium", ep, "anon", resp,
                    f"anon got {resp.status}: not 401/403, so the request got past authentication and was stopped by a business rule")
        if k in admin_only and "user_a" in api.roles:
            probes += 1
            resp = api.call("user_a", ep["method"], fill(ep["path"], {}), body)
            if resp.ok:
                add("PRIV-ESC", "high", ep, "user_a", resp, f"plain user got {resp.status} on admin-only endpoint")
    res = {"engine": "authz", "probes": probes, "findings": findings, "notes": notes + setup_failed, "setup_failed": setup_failed,
           "inferred_public": sorted(inferred)}          # not in `notes`: inferring from the document is not a limitation of the run
    if notes:
        extra = f" (+{len(setup_failed)} setup failure(s))" if setup_failed else ""
        return trust.mark(res, trust.DEGRADED, f"{len(notes)} probe group(s) skipped or limited{extra}: " + notes[0][:140])
    if setup_failed:
        return trust.mark(res, trust.SETUP_FAILED, f"{len(setup_failed)} setup failure(s), probes did not run: " + setup_failed[0][:140])
    return trust.mark(res, trust.RAN_OK)
