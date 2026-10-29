#!/usr/bin/env python
"""Oracle proposer: ask an LLM for DOMAIN RULES (the part an OpenAPI document does not state) and keep only the rules that survive a
mechanical check. The LLM never writes code; it writes data that logic_engine.py executes with read-back.

  python toolkit/rules_from_llm.py --openapi path/to/openapi.json [--base-spec qa-spec.py] [--out qa-spec.llm.py]
         --provider NAME --key-env VAR --api-url URL --model MODEL [--max-rules 5] [--dry-run]

Why this design (tree of thoughts)
  (A) The LLM writes the whole qa-spec.py (toolkit/synthesize.py): flexible, but one syntax slip or invented endpoint breaks the file,
      and SkyCodein cannot even take the prompt (8000-character context, 2048 output tokens).
  (B) The LLM fills a fixed template of knobs (PUBLIC, OWNER, ...): safe, but our engines now infer most knobs themselves.
  (C) The LLM proposes LOGIC_RULES (declared invariants), a small JSON language with six kinds; this module validates every rule
      against the OpenAPI document (paths, methods, body fields, enum values, read-back fields) and drops what does not fit: CHOSEN.
      It targets exactly what the engines cannot guess: formulas and limits that live in the product's head, not in the contract.
Honest limits: the rule language is narrow (no arithmetic across two objects); a rule that is wrong for a legal API produces a false
positive at severity high (declared rules are trusted), so rules are measured on a clean variant before they are believed;
the digest is cut to fit a small context, so large APIs are only partly shown (the output says how many operations).
The LLM helper is OPTIONAL and OFF by default: the core engines never import this module. Calling it needs an explicit opt-in
(--provider, --key-env, --api-url or QA_LLM_API_URL, --model or QA_LLM_MODEL); without one it stops before any network call.
The dry run (--dry-run) makes no network call and needs no opt-in.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "engine"))
import synthesize as S  # noqa: E402
from api import endpoints, resolve  # noqa: E402
from logic_engine import KINDS  # noqa: E402

DIGEST_BUDGET = 4300
SYSTEM = """You design business-rule checks for an automated API tester. From the endpoint digest propose at most {n} rules that a correct implementation must satisfy and that a typical implementation bug would break: money and balances, quantities and limits, refunds and caps, single-use codes, state transitions. Output ONLY JSON: {{"rules":[...]}}.
Rule: {{"name","kind","setup":[{{"call":"METHOD /path","body":{{}},"save":"x","save_from":"optional response field holding the id, default id"}}],"acts":[{{"call":"METHOD /path/{{x}}/verb","body":{{}}}}],"repeat":1,"read":"/path/{{x}}"}} plus the keys of its kind. "read" is a GET path whose answer is an object that contains the checked field.
Kinds: non_negative {{field,min}}; bounded_by {{field, bound_field OR bound_value}}; conservation {{act:{{call,body}}, field, delta_field, direction:"decrease"|"increase"}} (field changes by exactly |body[delta_field]| when the act is accepted); monotone_state {{field,order:[..],terminal:[..]}}; unique_use {{field, max_field OR max_value, repeat}}; sum_of_parts {{total_field,lines_field,price_field,qty_field}}.
Use ONLY paths, fields and enum values shown in the digest. {{x}} placeholders are filled from earlier setup saves. Never propose a rule that a legal implementation could break (a documented overdraft, an optional discount)."""


# ---------- compact digest of the OpenAPI document ----------

def _props(schema, spec, limit=9):
    schema = resolve(schema or {}, spec)
    props = schema.get("properties") or {}
    req = set(schema.get("required") or [])
    out = []
    for name, sch in list(props.items())[:limit]:
        sch = resolve(sch, spec)
        t = sch.get("type", "obj")
        enum = sch.get("enum")
        extra = ("=" + "|".join(map(str, enum[:5]))) if isinstance(enum, list) else ""
        lo, hi = sch.get("minimum"), sch.get("maximum")
        extra += (f"[{lo if lo is not None else ''}..{hi if hi is not None else ''}]") if (lo is not None or hi is not None) else ""
        out.append(f"{name}:{t}{extra}{'*' if name in req else ''}")
    return ",".join(out)


def response_props(spec, path, method):
    """Names of the top-level properties of the first 2xx JSON response of an operation (empty when it declares none)."""
    node = ((spec.get("paths") or {}).get(path) or {}).get(method.lower()) or {}
    for code, resp in (node.get("responses") or {}).items():
        if str(code).startswith("2") and isinstance(resp, dict):
            sch = (((resp.get("content") or {}).get("application/json") or {}).get("schema"))
            if sch:
                return list((resolve(sch, spec).get("properties") or {}).keys())
    return []


def digest(spec, budget=DIGEST_BUDGET):
    """(text, shown, total): one line per operation, '*' marks required fields, cut at `budget` characters."""
    eps = endpoints(spec)
    lines, size, shown = [], 0, 0
    for ep in eps:
        body = _props(ep.get("body_schema"), spec) if ep.get("body_schema") else ""
        resp = ",".join(response_props(spec, ep["path"], ep["method"])[:10])
        line = f"{ep['method']} {ep['path']}" + (f" body{{{body}}}" if body else "") + (f" ->{{{resp}}}" if resp else "")
        line = line[:230]
        if size + len(line) + 1 > budget:
            break
        lines.append(line)
        size += len(line) + 1
        shown += 1
    return "\n".join(lines), shown, len(eps)


def build_prompt(spec, max_rules=5, budget=DIGEST_BUDGET):
    text, shown, total = digest(spec, budget)
    note = "" if shown == total else f"\n(only {shown} of {total} operations are shown)"
    return SYSTEM.format(n=max_rules), "Endpoint digest ('*' = required, [a..b] = bounds):\n" + text + note, shown, total


# ---------- the LLM call ----------

RETRY_STATUS = (429, 500, 502, 503, 504, 524)       # 524/502: the gateway in front of the service gave up (about 100 s), often because it is busy


def call_llm(system, user, cfg, key, tries=3, idle_timeout=100, sleep=time.sleep):
    """One STREAMING chat call with the provider preset -> (text, usage, finish_reason).

    Why streaming: the hosted service sits behind a gateway that cuts a request after about 100 s without a response, and it answers
    one request at a time; a long answer sent as one block dies with 524 even when the model is fine. With stream=true the first byte
    arrives with the first token and the gateway stays quiet. `idle_timeout` is the longest silence between two chunks we accept.
    A 429/5xx/524 or a silent socket is retried after a growing pause (the service is serial: hammering it makes the queue longer)."""
    payload = {"model": cfg["model"], "temperature": 0.2, "max_tokens": cfg["max_tokens"], "stream": True,
               "stream_options": {"include_usage": True},
               "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    if cfg.get("json_mode"):
        payload["response_format"] = {"type": "json_object"}
    req = urllib.request.Request(cfg["api_url"], data=json.dumps(payload).encode(),
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json", "User-Agent": "qa-testing/0.1"})
    host = urllib.parse.urlparse(cfg["api_url"])
    if host.scheme == "http" and host.hostname not in ("127.0.0.1", "localhost", "::1") \
            and os.environ.get("QA_ALLOW_PLAINTEXT_PROVIDER") != "1":
        raise SystemExit(f"refusing to send the API key over plaintext HTTP to {host.hostname} (see synthesize.py)")
    last = ""
    for attempt in range(tries):
        try:
            text, usage, finish = [], {}, None
            with S._OPENER.open(req, timeout=idle_timeout) as r:      # no redirects: the key must not follow one
                for raw in r:
                    line = raw.decode("utf-8", "replace").strip()
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    chunk = json.loads(data)
                    usage = chunk.get("usage") or usage
                    for choice in chunk.get("choices") or []:
                        text.append((choice.get("delta") or {}).get("content") or "")
                        finish = choice.get("finish_reason") or finish
            return "".join(text), usage, finish
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code not in RETRY_STATUS:
                raise SystemExit(f"LLM call failed: {last} {e.read().decode(errors='replace')[:200]}")
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            last = f"{type(e).__name__}: {str(e)[:80]}"
        if attempt < tries - 1:
            sleep(30 * (attempt + 1))
    raise SystemExit(f"LLM call failed after {tries} tries ({last}); the service may be busy or down: nothing was written")


def parse_json(text):
    """The first JSON object in the answer (fences and prose around it are ignored)."""
    text = re.sub(r"^```[a-z]*\s*|```\s*$", "", text.strip(), flags=re.M)
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in the answer")
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            esc = (not esc) and ch == "\\"
            if ch == '"' and not esc:
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unterminated JSON object")


# ---------- mechanical validation ----------

def _norm(path):
    return re.sub(r"\{[^}]*\}", "{}", path)


def _op(spec, method, path):
    """(path template, operation node) of the spec path equal to `path` once placeholders are blanked, or (None, None)."""
    for p, item in (spec.get("paths") or {}).items():
        if _norm(p) == _norm(path) and isinstance(item, dict) and method.lower() in item:
            return p, item[method.lower()]
    return None, None


def _body_ok(spec, tpl_path, method, body):
    """None when every body field exists in the operation's request schema (enum values included), else the reason."""
    if not isinstance(body, dict) or not body:
        return None
    ep = next((e for e in endpoints(spec) if e["path"] == tpl_path and e["method"] == method), None)
    schema = resolve((ep or {}).get("body_schema") or {}, spec)
    props = schema.get("properties")
    if not props:
        return None
    for name, value in body.items():
        if name not in props:
            return f"body field {name!r} is not in the request schema of {method} {tpl_path}"
        enum = resolve(props[name], spec).get("enum")
        if isinstance(enum, list) and value not in enum and not (isinstance(value, str) and value.startswith("{")):
            return f"{name}={value!r} is not one of {enum}"
    return None


NEEDS = {"non_negative": ("field",), "bounded_by": ("field",), "conservation": ("act", "field", "delta_field"),
         "monotone_state": ("field",), "unique_use": ("field",), "sum_of_parts": ()}


def _bad_text(node):
    """First string anywhere in the rule that contains a control character or is absurdly long, else None."""
    if isinstance(node, str):
        return "a string with a control character" if any(ord(c) < 32 or ord(c) == 127 for c in node) else (
            "a string longer than 300 characters" if len(node) > 300 else None)
    if isinstance(node, dict):
        return next((r for k, v in node.items() for r in (_bad_text(k), _bad_text(v)) if r), None)
    if isinstance(node, list):
        return next((r for v in node for r in [_bad_text(v)] if r), None)
    return None


def validate_rule(rule, spec):
    """None when the rule is usable, else the reason it is dropped."""
    if not isinstance(rule, dict) or not isinstance(rule.get("name"), str):
        return "not an object with a name"
    bad = _bad_text(rule)
    if bad:
        return f"contains {bad}"
    kind = rule.get("kind")
    if kind not in KINDS:
        return f"unknown kind {kind!r}"
    for k in NEEDS[kind]:
        if k not in rule:
            return f"kind {kind} needs {k!r}"
    if kind == "bounded_by" and not ("bound_field" in rule or "bound_value" in rule):
        return "bounded_by needs bound_field or bound_value"
    if kind == "unique_use" and not ("max_field" in rule or "max_value" in rule):
        return "unique_use needs max_field or max_value"
    saved = set()
    steps = list(rule.get("setup") or []) + list(rule.get("acts") or []) + ([rule["act"]] if isinstance(rule.get("act"), dict) else [])
    if not steps or not (rule.get("acts") or rule.get("act")):
        return "no acts"
    for step in list(rule.get("setup") or []):
        r = _check_step(step, spec, saved)
        if r:
            return r
        if step.get("save"):
            saved.add(step["save"])
    for step in list(rule.get("acts") or []) + ([rule["act"]] if isinstance(rule.get("act"), dict) else []):
        r = _check_step(step, spec, saved)
        if r:
            return r
    read = rule.get("read")
    if not isinstance(read, str) or not read.startswith("/"):
        return "no read path"
    for name in re.findall(r"\{([^}]*)\}", read):
        if name not in saved:
            return f"read path uses {{{name}}} which no setup step saves"
    rp, node = _op(spec, "GET", read)
    if rp is None:
        return f"read path GET {read} is not in the OpenAPI document"
    fields = response_props(spec, rp, "GET")
    for k in ("field", "bound_field", "total_field", "lines_field"):
        if isinstance(rule.get(k), str) and fields and rule[k] not in fields:
            return f"{k}={rule[k]!r} is not a field of the GET {rp} response ({', '.join(fields[:8])})"
    return None


def _check_step(step, spec, saved):
    if not isinstance(step, dict) or not isinstance(step.get("call"), str) or " " not in step["call"]:
        return "a step has no 'METHOD /path' call"
    method, path = step["call"].split(" ", 1)
    method = method.upper()
    tpl, node = _op(spec, method, path)
    if tpl is None:
        return f"{method} {path} is not in the OpenAPI document"
    for name in re.findall(r"\{([^}]*)\}", path):
        if name not in saved:
            return f"{method} {path} uses {{{name}}} which no earlier setup step saves"
    why = _body_ok(spec, tpl, method, step.get("body"))
    if why:
        return why
    return None


def validate(rules, spec):
    kept, dropped = [], []
    for rule in rules if isinstance(rules, list) else []:
        why = validate_rule(rule, spec)
        (dropped if why else kept).append((rule.get("name", "?") if isinstance(rule, dict) else "?", why) if why else rule)
    return kept, dropped


# ---------- output ----------

def render(base_text, kept, meta):
    header = (f"\n\n# --- LOGIC_RULES proposed by rules_from_llm.py ({meta.get('model', '?')}, {date.today().isoformat()}): "
              f"{len(kept)} kept, {meta.get('dropped', 0)} dropped by validation ---\n")
    # The rules come from an LLM: they are data, never source. repr() of the JSON text is a correctly escaped Python string literal for ANY
    # content (quotes, triple quotes, newlines, backslashes), so nothing in a rule can end the literal and become code of the spec.
    body = ("import json as _json\nLOGIC_RULES = list(globals().get('LOGIC_RULES', [])) + _json.loads("
            + repr(json.dumps(kept, ensure_ascii=True)) + ")\n")
    return base_text.rstrip("\n") + header + body        # the header holds only our own values (model name, counts), never LLM text


def propose(spec, provider=None, max_rules=5, caller=None, key=None, key_env=None, api_url=None, model=None):
    """-> {'kept': [...], 'dropped': [(name, why)], 'raw': text, 'usage': {...}, 'shown': n, 'total': n}

    A network call (caller is None) needs an explicit opt-in: provider, key_env, api_url and model (see synthesize.provider_settings);
    the key is read from the environment variable named by key_env unless key is given. `caller` replaces the network (tests)."""
    if caller is None:
        cfg = S.provider_settings(provider, api_url, model, None, key_env)     # refuses before any network use
        key = key or os.environ.get(cfg["key_env"])
        if not key:
            raise SystemExit(f"Set {cfg['key_env']} in the environment or the .env file (root of qa-testing); --key-env names it")
    else:
        cfg = {"context_chars": S.PROVIDERS.get(provider or "", {}).get("context_chars"), "model": model or "", "api_url": api_url or ""}
    cfg["json_mode"] = provider == "skycodein"
    system, user, shown, total = build_prompt(spec, max_rules, DIGEST_BUDGET if cfg["context_chars"] else 20000)
    S.check_context(system, user, cfg["context_chars"])
    out = (caller or (lambda s, u: call_llm(s, u, cfg, key)))(system, user)
    text, usage = out[0], out[1]
    finish = out[2] if len(out) > 2 else None
    try:
        rules = parse_json(text).get("rules", [])
    except (ValueError, json.JSONDecodeError) as exc:
        why = f"unparseable: {exc}" + (" (the answer was cut at the token limit: ask for fewer rules)" if finish == "length" else "")
        return {"kept": [], "dropped": [("(answer)", why)], "raw": text, "usage": usage, "shown": shown, "total": total}
    kept, dropped = validate(rules, spec)
    return {"kept": kept, "dropped": dropped, "raw": text, "usage": usage, "shown": shown, "total": total, "model": cfg["model"]}


def main():
    p = argparse.ArgumentParser(description="Propose LOGIC_RULES with an LLM and keep the mechanically valid ones")
    p.add_argument("--openapi", required=True)
    p.add_argument("--base-spec", help="existing qa-spec.py; the output is this file plus the proposed rules")
    p.add_argument("--out", default="qa-spec.llm.py")
    p.add_argument("--provider", choices=sorted(S.PROVIDERS), default=None,
                   help="REQUIRED to opt in (no default); see synthesize.py")
    p.add_argument("--key-env", default=None, help="REQUIRED to opt in: name of the environment variable holding the API key")
    p.add_argument("--api-url", default=None, help="REQUIRED to opt in unless QA_LLM_API_URL is set")
    p.add_argument("--model", default=None, help="REQUIRED to opt in unless QA_LLM_MODEL is set")
    p.add_argument("--max-rules", type=int, default=5)
    p.add_argument("--dry-run", action="store_true", help="print the prompt size and stop")
    a = p.parse_args()
    env_file = HERE.parent / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
    spec = json.loads(Path(a.openapi).read_text(encoding="utf-8"))
    system, user, shown, total = build_prompt(spec, a.max_rules)
    print(f"prompt: {len(system) + len(user)} characters ({shown}/{total} operations shown)", file=sys.stderr)
    if a.dry_run:
        return
    res = propose(spec, a.provider, a.max_rules, key_env=a.key_env, api_url=a.api_url, model=a.model)     # refuses without opt-in
    for name, why in res["dropped"]:
        print(f"  DROPPED {name}: {why}", file=sys.stderr)
    print(f"{len(res['kept'])} rule(s) kept, {len(res['dropped'])} dropped; tokens {res['usage']}", file=sys.stderr)
    base = Path(a.base_spec).read_text(encoding="utf-8") if a.base_spec else '"""qa-spec generated from rules proposed by an LLM."""\n'
    Path(a.out).write_text(render(base, res["kept"], {"model": res.get("model"), "dropped": len(res["dropped"])}), encoding="utf-8")
    Path(a.out).with_suffix(".llm.json").write_text(json.dumps({"raw": res["raw"], "dropped": res["dropped"], "usage": res["usage"]}, indent=1),
                                                    encoding="utf-8")
    print(f"wrote {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
