"""Schema-aware static checks: things semgrep cannot see because they need the DATA MODEL and the CODE together.

  python static_checks.py <project-dir> [--out qa-report/static.md]

Checks (all candidates; the dynamic engines / a PoC decide):
  UNIQUE-FROM-RANDOM  a column declared unique (Prisma @unique, Django unique=True, SQLAlchemy unique=True, Mongoose unique:true)
                      is filled from a generator with a small random space (Math.random()*9000, randint(1000, 9999), 36^k ...).
                      Reports the space, and the number of rows at which a collision is already 50 % likely (birthday bound).
  ENUM-CAST           request input is cast to a Prisma / TS enum type (`x as TicketType`) in a handler without validation:
                      invalid values reach the ORM and become 500s.
  ERROR-ECHO          catch block returns the raw exception message / stack to the client.
  MASS-ASSIGN-SPREAD  the request body (or a spread of it) is passed straight into an ORM create / update.
  ROUTE-NO-AUTH       Next.js route handler that never touches a session / token helper (review: public on purpose?).
  RANDOM-TOKEN        Math.random / random.random used to build tokens, codes, passwords, ids that look security relevant.
Heuristic and regex based on purpose: no build, no dependencies, JS/TS + Python + Prisma.
"""
import argparse
import math
import re
import sys
from pathlib import Path

SKIP_DIRS = {"node_modules", ".next", ".git", "venv", ".venv", "__pycache__", "dist", "build", "qa-report", ".claude", "coverage"}
CODE_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".py"}


def files(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and p.suffix in CODE_EXT | {".prisma"} and not (set(p.relative_to(root).parts) & SKIP_DIRS):
            yield p


def rel(p: Path, root: Path) -> str:
    return str(p.relative_to(root)).replace("\\", "/")


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


# ---------------------------------------------------------------- model discovery
def unique_fields(root: Path) -> dict[str, list[str]]:
    """{field_name: [where declared]} for unique string-ish columns."""
    out: dict[str, list[str]] = {}
    for p in files(root):
        t = p.read_text(encoding="utf-8", errors="replace")
        pats = []
        if p.suffix == ".prisma":
            pats = [r"^\s*(\w+)\s+String\??\s+[^\n]*@unique"]
        elif p.suffix == ".py":
            pats = [r"^\s*(\w+)\s*=\s*(?:models|db)\.(?:Char|Text|String|Slug)\w*\([^\n]*unique\s*=\s*True",
                    r"^\s*(\w+)\s*=\s*(?:db\.)?Column\([^\n]*String[^\n]*unique\s*=\s*True"]
        else:
            pats = [r"(\w+)\s*:\s*\{[^}\n]*type\s*:\s*String[^}\n]*unique\s*:\s*true", r"(\w+)\s*:\s*\{[^}\n]*unique\s*:\s*true[^}\n]*\}"]
        for pat in pats:
            for m in re.finditer(pat, t, re.M):
                out.setdefault(m.group(1), []).append(f"{rel(p, root)}:{line_of(t, m.start())}")
    return out


def function_bodies(root: Path) -> dict[str, tuple[str, str, int]]:
    """{name: (body_text, file, line)} for JS/TS functions and Python defs (body = next ~30 lines / until matching brace)."""
    out = {}
    for p in files(root):
        if p.suffix == ".prisma":
            continue
        t = p.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"(?:function\s+(\w+)\s*\([^)]*\)[^{]*\{)|(?:(?:const|let)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)[^=]*=>\s*\{?)|(?:def\s+(\w+)\s*\([^)]*\)[^:]*:)", t):
            name = m.group(1) or m.group(2) or m.group(3)
            out.setdefault(name, (t[m.end():m.end() + 900], rel(p, root), line_of(t, m.start())))
    return out


def random_space(body: str) -> tuple[float, str] | None:
    """Estimated number of distinct values a generator body can produce (None = not random / unknown)."""
    best = None

    def consider(space, why):
        nonlocal best
        if space > 1 and (best is None or space < best[0]):
            best = (float(space), why)

    for m in re.finditer(r"Math\.random\(\)\s*\*\s*(\d[\d_]*)", body):
        consider(int(m.group(1).replace("_", "")), f"Math.random()*{m.group(1)}")
    for m in re.finditer(r"randint\(\s*(\d+)\s*,\s*(\d+)\s*\)", body):
        consider(int(m.group(2)) - int(m.group(1)) + 1, f"randint({m.group(1)}, {m.group(2)})")
    for m in re.finditer(r"random\.randrange\(\s*(\d+)\s*(?:,\s*(\d+))?\s*\)", body):
        lo, hi = (0, int(m.group(1))) if m.group(2) is None else (int(m.group(1)), int(m.group(2)))
        consider(hi - lo, m.group(0))
    for m in re.finditer(r"Math\.random\(\)\.toString\(36\)\.(?:slice|substring|substr)\(\s*(\d+)\s*(?:,\s*(\d+))?\s*\)", body):
        n = (int(m.group(2)) - int(m.group(1))) if m.group(2) else 8
        consider(36 ** max(n, 1), f"toString(36) x {n} chars")
    for m in re.finditer(r"random\.choices?\([^)]*k\s*=\s*(\d+)", body):
        consider(36 ** int(m.group(1)), f"random.choices k={m.group(1)}")
    if best is None and re.search(r"Math\.random\(\)|random\.random\(\)", body):
        return (1e6, "Math.random() (space unknown, assumed small)")
    return best


def check_unique_random(root: Path) -> list[dict]:
    findings = []
    uniq = unique_fields(root)
    if not uniq:
        return findings
    funcs = function_bodies(root)
    for p in files(root):
        if p.suffix == ".prisma":
            continue
        t = p.read_text(encoding="utf-8", errors="replace")
        for field, where in uniq.items():
            for m in re.finditer(rf"\b{field}\b\s*[:=]\s*(?:await\s+)?(\w+)\(", t):
                fn = m.group(1)
                if fn not in funcs:
                    continue
                body, fpath, fline = funcs[fn]
                sp = random_space(body)
                if not sp:
                    continue
                space, why = sp
                scoped = bool(re.search(r"getFullYear|strftime|\.year\b|toISOString\(\)\.slice", body))
                n50 = 1.1774 * math.sqrt(space)
                sev = "high" if n50 < 10_000 else "medium" if n50 < 1_000_000 else "low"
                findings.append({
                    "kind": "UNIQUE-FROM-RANDOM", "severity": sev, "file": f"{rel(p, root)}:{line_of(t, m.start())}",
                    "detail": f"unique column `{field}` ({where[0]}) is filled by {fn}() ({fpath}:{fline}) from a random space of ~{space:,.0f} ({why}). "
                              f"Collision is 50% likely after ~{n50:,.0f} rows{' per year (value contains the year)' if scoped else ''}; "
                              f"creates then fail with a unique-constraint error (usually surfaced as a 500)."})
    return findings


# ---------------------------------------------------------------- handlers
def handler_files(root: Path):
    for p in files(root):
        if p.suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs"):
            rp = rel(p, root)
            if re.search(r"(^|/)(app|pages)/.*(api|route)", rp) or re.search(r"route\.(ts|js)$", rp) or re.search(r"(routes?|controllers?|api)/", rp):
                yield p


def prisma_enums(root: Path) -> set[str]:
    names = set()
    for p in files(root):
        if p.suffix == ".prisma":
            names |= set(re.findall(r"^\s*enum\s+(\w+)", p.read_text(encoding="utf-8", errors="replace"), re.M))
    return names


def check_handlers(root: Path) -> list[dict]:
    findings = []
    enums = prisma_enums(root)
    for p in handler_files(root):
        t = p.read_text(encoding="utf-8", errors="replace")
        r = rel(p, root)
        reads_body = re.search(r"\.json\(\)|req\.body|request\.body", t)
        if enums and reads_body:
            for m in re.finditer(r"\bas\s+(" + "|".join(sorted(enums)) + r")\b", t):
                window = t[max(0, m.start() - 400):m.end() + 100]
                if not re.search(r"Object\.values\(|\.includes\(|safeParse|\.parse\(|z\.enum|in\s+" + m.group(1), window):
                    findings.append({"kind": "ENUM-CAST", "severity": "medium", "file": f"{r}:{line_of(t, m.start())}",
                                     "detail": f"request input cast to enum `{m.group(1)}` without validation: invalid values reach the ORM (500 instead of 400)"})
        for m in re.finditer(r"catch\s*(?:\((\w+)\))?\s*\{(.{0,400}?)\}\s*\n", t, re.S):
            var, block = m.group(1), m.group(2)
            if re.search(r"json\([^)]*error\s*:\s*(?:msg|message|String\(\w+\)|\w+\.message|\w+\.stack|\w+\b)\s*[,}]", block) and \
                    not re.search(r'error\s*:\s*"', block.split("error")[1] if "error" in block else ""):
                if re.search(r"error\s*:\s*(msg|message|String\(|" + (re.escape(var) if var else "e") + r"\b)", block):
                    findings.append({"kind": "ERROR-ECHO", "severity": "low", "file": f"{r}:{line_of(t, m.start())}",
                                     "detail": "catch block returns the raw exception message to the client (leaks SDK / DB / path details)"})
        for m in re.finditer(r"\b(?:create|update|updateMany|upsert|insert\w*|save)\s*\(\s*\{[^}]*\bdata\s*:\s*(?:body|req\.body|await req\.json\(\)|\{\s*\.\.\.(?:body|req\.body))", t):
            findings.append({"kind": "MASS-ASSIGN-SPREAD", "severity": "high", "file": f"{r}:{line_of(t, m.start())}",
                             "detail": "request body is passed straight into an ORM write: client controls every column (role, ownerId, price, ...)"})
        for m in re.finditer(r"\.(?:create|insert\w*)\(\s*(?:req\.body|request\.body)\s*\)|\bModel\.create\(\s*(?:body|req\.body)\b", t):
            findings.append({"kind": "MASS-ASSIGN-SPREAD", "severity": "high", "file": f"{r}:{line_of(t, m.start())}",
                             "detail": "request body is passed straight into an ORM create"})
        if re.search(r"(^|/)route\.(ts|js)$", r) and "/api/" in "/" + r:
            exported = re.findall(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b", t)
            if exported and not re.search(r"getServerSession|getToken|\bauth\(|currentUser|requireAuth|verifyToken|jwt\.verify|getSession|NextAuth\(|handlers\b", t):
                findings.append({"kind": "ROUTE-NO-AUTH", "severity": "info", "file": r,
                                 "detail": f"{'/'.join(exported)} handler never checks a session/token: public on purpose?"})
        for m in re.finditer(r"(\w*(?:token|secret|password|passwd|otp|code|apikey|api_key|nonce|reset)\w*)\s*[:=][^;\n]*(?:Math\.random\(\)|random\.random\(\))", t, re.I):
            findings.append({"kind": "RANDOM-TOKEN", "severity": "medium", "file": f"{r}:{line_of(t, m.start())}",
                             "detail": f"`{m.group(1)}` is built from a non-cryptographic RNG (use crypto.randomBytes / secrets)"})
    for p in files(root):
        if p.suffix == ".py":
            t = p.read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r"(\w*(?:token|secret|password|otp|reset|nonce)\w*)\s*=[^\n]*\brandom\.(?:random|randint|choice|choices|randrange)\(", t, re.I):
                findings.append({"kind": "RANDOM-TOKEN", "severity": "medium", "file": f"{rel(p, root)}:{line_of(t, m.start())}",
                                 "detail": f"`{m.group(1)}` is built from `random` (use secrets)"})
    return findings


def run(root: Path) -> list[dict]:
    return check_unique_random(root) + check_handlers(root)


def render(findings: list[dict]) -> str:
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    lines = ["# Static (schema-aware) checks", ""]
    for f in sorted(findings, key=lambda f: (order[f["severity"]], f["kind"], f["file"])):
        lines.append(f"- **{f['severity']} {f['kind']}** `{f['file']}` — {f['detail']}")
    if not findings:
        lines.append("- nothing found")
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--out")
    a = ap.parse_args()
    res = run(Path(a.root).resolve())
    text = render(res)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text, encoding="utf-8")
    sys.stdout.buffer.write((text + "\n").encode("utf-8", "replace"))
