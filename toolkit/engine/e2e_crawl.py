"""Browser layer: crawl the running app as every role and report what only a real browser sees.

  python -m uv run --no-project --python 3.12 --with playwright python e2e_crawl.py --spec qa-report/qa-spec.py --out qa-report/e2e \
        [--base-url http://127.0.0.1:8765] [--max-pages 40] [--browser msedge|chrome|chromium]

Run it through safe_run.py (it exports QA_BASE_URL). Roles come from qa-spec.py setup(): a "Cookie" header is converted to browser
cookies (NextAuth / Django / Flask sessions). For other auth schemes define in qa-spec.py
  E2E_LOGIN = {"user_a": fn(page, base_url)}      # drive the login form / set localStorage
Needs a Chromium-family browser: Edge or Chrome are used if installed (no download), else `playwright install chromium`.

Per page: console errors, page exceptions, failed requests, HTTP >= 400 responses, horizontal overflow at 375 px (mobile), images
without alt, controls without an accessible name, inputs without a label, missing <title> / lang.
Cross-role: pages under /admin (or listed in E2E_ADMIN_PATHS) that a non-admin role can actually render.
Forms: filled with sample values and submitted with a double click: more than one successful write request = DOUBLE-SUBMIT.

Limit (safety): the crawl only enqueues same-host links and aborts navigation when the final URL leaves the base
host:port (cookies stay scoped by Playwright, but a 302 off-machine is still a second HTTP client). Off-machine
final URLs are recorded as E2E-OFFHOST findings and not followed further.
The --base-url must be an http(s) URL on a loopback host, or the crawl refuses to start (api.assert_local).
NOT covered: the browser itself is launched without a proxy and without request routing. A page's own third-party
scripts, images, beacons, and a form whose action points off-host are still fetched by the browser (a form double-click
submits to that host). Only the navigation target is checked. Do not read this crawl as "no outside traffic".
"""
import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api as api_mod  # noqa: E402

SKIP_HREF = re.compile(r"logout|signout|sign-out|log-out|delete|remove|destroy|mailto:|tel:|javascript:", re.I)
A11Y_JS = """() => {
  const out = {overflow: document.documentElement.scrollWidth > window.innerWidth + 1, noAlt: 0, noName: 0, noLabel: 0,
               title: document.title, lang: document.documentElement.lang};
  document.querySelectorAll('img:not([alt])').forEach(() => out.noAlt++);
  document.querySelectorAll('button, a[href], [role=button]').forEach(el => {
    const name = (el.innerText || el.getAttribute('aria-label') || el.getAttribute('title') || el.querySelector('img[alt]')?.alt || '').trim();
    if (!name) out.noName++;
  });
  document.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]), select, textarea').forEach(el => {
    const id = el.id; const has = el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || (id && document.querySelector('label[for="' + id + '"]')) || el.closest('label') || el.getAttribute('placeholder');
    if (!has) out.noLabel++;
  });
  return out;
}"""


def group(findings):
    """Same finding on many pages (layout-level problems) -> one line listing the pages."""
    buckets, out = {}, []
    for f in findings:
        role_page = f["endpoint"].split(" ", 1)
        if f["kind"] in ("E2E-MOBILE-OVERFLOW", "E2E-A11Y", "E2E-CONSOLE", "E2E-HTTP") and len(role_page) == 2:
            norm = re.sub(r"[0-9a-z]{20,}", "{id}", role_page[1])
            buckets.setdefault((f["kind"], f["severity"], re.sub(r"[0-9a-z]{20,}", "{id}", f["detail"])), set()).add(f"{role_page[0]}:{norm}")
        else:
            out.append(f)
    for (kind, sev, detail), pages in buckets.items():
        listed = sorted(pages)
        out.append({"kind": kind, "severity": sev, "endpoint": f"{len(listed)} page(s)", "detail": f"{detail} -- " + ", ".join(listed[:8]) + (" ..." if len(listed) > 8 else "")})
    return out


def load_spec(path):
    s = importlib.util.spec_from_file_location("qa_spec", path)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def cookies_from_header(header: str, base: str):
    host = urlparse(base).hostname
    return [{"name": k.strip(), "value": v, "domain": host, "path": "/"} for k, _, v in (p.partition("=") for p in header.split(";")) if k.strip()]


def launch(pw, which):
    errors = []
    for name in ([which] if which else ["msedge", "chrome", "chromium"]):
        try:
            return pw.chromium.launch(channel=None if name == "chromium" else name, headless=True)
        except Exception as exc:
            errors.append(f"{name}: {str(exc)[:120]}")
    raise SystemExit("no browser available: " + "; ".join(errors) + "\n  -> python -m playwright install chromium")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True)
    ap.add_argument("--base-url", default=os.environ.get("QA_BASE_URL"))
    ap.add_argument("--out", default="qa-report/e2e")
    ap.add_argument("--max-pages", type=int, default=40)
    ap.add_argument("--browser")
    ap.add_argument("--start", default="/")
    a = ap.parse_args()
    if not a.base_url:
        raise SystemExit("--base-url or QA_BASE_URL required")
    api_mod.assert_local(a.base_url)
    base = a.base_url.rstrip("/")
    qa = load_spec(a.spec)
    api = api_mod.Api(base)
    roles = (qa.setup(api) if hasattr(qa, "setup") else {}) or {}
    admin_paths = list(getattr(qa, "E2E_ADMIN_PATHS", ["/admin"]))
    custom_login = getattr(qa, "E2E_LOGIN", {})
    from playwright.sync_api import sync_playwright

    findings, notes, pages_by_role = [], [], {}
    form_stats = {"forms": 0, "writes": 0, "double": 0}

    def add(kind, sev, where, detail):
        key = (kind, where, detail[:80])
        if key not in {(f["kind"], f["endpoint"], f["detail"][:80]) for f in findings}:
            findings.append({"kind": kind, "severity": sev, "endpoint": where, "detail": detail})

    with sync_playwright() as pw:
        browser = launch(pw, a.browser)
        for role in ["anon"] + [r for r in roles if r != "anon"]:
            ctx = browser.new_context(viewport={"width": 1280, "height": 800})
            if role != "anon" and "Cookie" in roles.get(role, {}):
                ctx.add_cookies(cookies_from_header(roles[role]["Cookie"], base))
            page = ctx.new_page()
            if role in custom_login:
                custom_login[role](page, base)
            log = {"console": [], "failed": [], "http": []}
            page.on("console", lambda m: log["console"].append(m.text[:200]) if m.type == "error" else None)
            page.on("pageerror", lambda e: log["console"].append("pageerror: " + str(e)[:200]))
            page.on("requestfailed", lambda r: log["failed"].append(f"{r.method} {r.url[:100]} {r.failure}"))
            page.on("response", lambda r: log["http"].append((r.status, r.request.method, r.url)) if r.status >= 400 and "favicon" not in r.url else None)
            seen, queue, rendered = set(), [a.start], []
            while queue and len(seen) < a.max_pages:
                path = queue.pop(0)
                url = urljoin(base + "/", path)
                if urlparse(url).netloc != urlparse(base).netloc or url in seen:
                    continue
                seen.add(url)
                for k in log:
                    log[k].clear()
                try:
                    resp = page.goto(url, wait_until="networkidle", timeout=60000)
                except Exception as exc:
                    add("E2E-NAV", "medium", f"{role} {path}", f"navigation failed: {str(exc)[:120]}")
                    continue
                landed = urlparse(page.url)
                base_p = urlparse(base)
                if landed.hostname not in ("localhost", "127.0.0.1", "::1") or (
                        landed.port or (443 if landed.scheme == "https" else 80)) != (
                        base_p.port or (443 if base_p.scheme == "https" else 80)):
                    add("E2E-OFFHOST", "high", f"{role} {path}",
                        f"navigation left the target host:port -> {page.url[:160]} (cookies may have followed; not crawled further)")
                    continue
                final = landed.path or "/"
                rendered.append((urlparse(url).path, final, resp.status if resp else 0))
                for text in log["console"][:3]:
                    add("E2E-CONSOLE", "medium", f"{role} {final}", text)
                for text in log["failed"][:3]:
                    add("E2E-REQUEST-FAILED", "medium", f"{role} {final}", text)
                for status, method, u in log["http"][:5]:
                    if not (status in (401, 403) and role == "anon"):
                        add("E2E-HTTP", "medium" if status >= 500 else "low", f"{role} {final}", f"{method} {urlparse(u).path} -> {status}")
                if resp and resp.status >= 500:
                    add("E2E-HTTP", "high", f"{role} {final}", f"page itself returned {resp.status}")
                page.set_viewport_size({"width": 375, "height": 700})
                info = page.evaluate(A11Y_JS)
                page.set_viewport_size({"width": 1280, "height": 800})
                if info["overflow"]:
                    add("E2E-MOBILE-OVERFLOW", "low", f"{role} {final}", "horizontal scroll at 375px width")
                if info["noAlt"]:
                    add("E2E-A11Y", "low", f"{role} {final}", f"{info['noAlt']} image(s) without alt")
                if info["noName"]:
                    add("E2E-A11Y", "low", f"{role} {final}", f"{info['noName']} button/link(s) without an accessible name")
                if info["noLabel"]:
                    add("E2E-A11Y", "low", f"{role} {final}", f"{info['noLabel']} form field(s) without label/placeholder")
                if not info["title"].strip():
                    add("E2E-A11Y", "low", f"{role} {final}", "page has no <title>")
                for href in page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))"):
                    if href and not SKIP_HREF.search(href) and not href.startswith("#"):
                        target = urljoin(url, href)
                        if urlparse(target).netloc == urlparse(base).netloc and target.split("#")[0] not in seen:
                            queue.append(target.split("#")[0])
                # forms: double submit
                if role != "anon":
                    for form in page.query_selector_all("form")[:2]:
                        btn = form.query_selector("button[type=submit], button:not([type]), input[type=submit]")
                        if not btn or not btn.is_visible():
                            continue
                        for el in form.query_selector_all("input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=file]), textarea"):
                            try:
                                typ = (el.get_attribute("type") or "text").lower()
                                if el.is_visible() and el.is_enabled():
                                    el.fill({"email": "qa@example.com", "number": "1", "password": "Passw0rd!x", "url": "http://127.0.0.1/"}.get(typ, "qa double submit"))
                            except Exception:
                                pass
                        for sel in form.query_selector_all("select"):
                            try:
                                opts = [o.get_attribute("value") for o in sel.query_selector_all("option") if o.get_attribute("value")]
                                if opts:
                                    sel.select_option(opts[0])
                            except Exception:
                                pass
                        writes = []
                        handler = lambda r: writes.append((r.status, r.request.method, urlparse(r.url).path)) if r.request.method in ("POST", "PUT", "PATCH") and "/_next/" not in r.url else None
                        page.on("response", handler)
                        try:
                            btn.dblclick(timeout=3000)
                            page.wait_for_timeout(1500)
                        except Exception:
                            pass
                        page.remove_listener("response", handler)
                        ok = [w for w in writes if w[0] < 300]
                        form_stats["forms"] += 1
                        form_stats["writes"] += len(ok)
                        if len(ok) >= 2 and len({w[2] for w in ok}) == 1:
                            add("E2E-DOUBLE-SUBMIT", "medium", f"{role} {final}", f"double click sent {len(ok)} successful {ok[0][1]} {ok[0][2]} requests (button not disabled / no dedupe)")
                        elif any(w[0] >= 500 for w in writes):
                            add("E2E-HTTP", "medium", f"{role} {final}", f"form submit -> {[w for w in writes if w[0] >= 500][0]}")
                        if page.url != url:
                            try:
                                page.goto(url, wait_until="networkidle", timeout=30000)
                            except Exception:
                                pass
            pages_by_role[role] = rendered
            ctx.close()
        browser.close()

    # cross-role: admin pages that a non-admin role renders (no redirect away, status 200)
    for role, rendered in pages_by_role.items():
        if role == "admin":                 # every other role, anon included, must not render an admin page
            continue
        for req_path, final, status in rendered:
            if any(req_path.startswith(p) for p in admin_paths) and final.startswith(tuple(admin_paths)) and status == 200:
                add("E2E-ADMIN-PAGE-ACCESS", "high", f"{role} {req_path}", f"{role} rendered an admin page (final URL {final}, status {status})")
    notes.append(f"forms submitted with a double click: {form_stats['forms']} (successful write requests seen: {form_stats['writes']}; "
                 "1 per form means the UI guards double submits)")
    findings[:] = group(findings)
    notes.append("pages visited: " + ", ".join(f"{r}={len(v)}" for r, v in pages_by_role.items()))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    result = {"engine": "e2e", "findings": findings, "notes": notes}
    (out / "e2e.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    lines = ["# E2E crawl", ""] + [f"- **{f['severity']} {f['kind']}** `{f['endpoint']}` — {f['detail']}" for f in findings] + [f"- note: {n}" for n in notes]
    (out / "e2e.md").write_text("\n".join(lines), encoding="utf-8")
    sys.stdout.buffer.write(("\n".join(lines) + f"\nTOTAL findings: {len(findings)}\n").encode("utf-8", "replace"))


if __name__ == "__main__":
    main()
