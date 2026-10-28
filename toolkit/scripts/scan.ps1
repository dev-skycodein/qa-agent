# Usage: powershell -File scan.ps1 [path] [-ApiUrl http://localhost:8000/openapi.json] [-ExcludePaths "^/(chat|search)"]
#   -> writes qa-report/* in target. ApiUrl must be LOCAL, never production.
param([string]$Path = ".", [string]$ApiUrl = "", [string]$ExcludePaths = "^/(chat|search)")
if ($ApiUrl -and ($ApiUrl -notmatch '^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?(/|$)')) {
  [Console]::Error.WriteLine("ApiUrl must be a local URL (127.0.0.1, localhost or [::1]); refusing $ApiUrl"); exit 2
}
if ($Path -match "['`"]") { [Console]::Error.WriteLine("path may not contain quote characters"); exit 2 }
$env:PYTHONUTF8 = "1"   # semgrep crashes on cp1252 when writing emoji
$out = Join-Path $Path "qa-report"; New-Item -ItemType Directory -Force $out | Out-Null

if (Get-Command semgrep -ErrorAction SilentlyContinue) {
  Write-Host "[semgrep] running"
  semgrep scan --metrics=off --config p/default --config p/owasp-top-ten --config p/secrets `
    --sarif -o (Join-Path $out "semgrep.sarif") $Path
  $learned = Join-Path $PSScriptRoot "..\rules\learned"
  if (Get-ChildItem $learned -Filter *.yaml -ErrorAction SilentlyContinue) {
    Write-Host "[semgrep] learned rules"
    semgrep scan --metrics=off --config $learned --sarif -o (Join-Path $out "semgrep-learned.sarif") $Path
  }
} else { Write-Host "[semgrep] missing -> pip install semgrep" }

if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
  Write-Host "[gitleaks] running"
  # git repo -> scan committed history only (gitignored .env/venv/.next = noise)
  $mode = if (Test-Path (Join-Path $Path ".git")) { "git" } else { "dir" }
  gitleaks $mode $Path --report-format json --report-path (Join-Path $out "gitleaks.json") --no-banner --redact
} else { Write-Host "[gitleaks] missing -> choco install gitleaks" }

if (Get-Command osv-scanner -ErrorAction SilentlyContinue) {
  Write-Host "[osv-scanner] running"
  # unpinned requirements*.txt -> osv guesses versions (noise). Resolve real pins with uv first.
  $locks = @()
  foreach ($req in Get-ChildItem $Path -Recurse -Filter "requirements*.txt" -ErrorAction SilentlyContinue |
           Where-Object { $_.FullName -notmatch "node_modules|venv|\.claude" }) {
    $lock = Join-Path $out ("resolved-" + $req.Directory.Name + "-" + $req.BaseName + ".txt")
    python -m uv pip compile $req.FullName -o $lock -q 2>$null
    if (Test-Path $lock) { $locks += "-L"; $locks += "requirements.txt:$lock" }
  }
  $npm = Get-ChildItem $Path -Recurse -Filter "package-lock.json" -ErrorAction SilentlyContinue |
         Where-Object { $_.FullName -notmatch "node_modules" }
  foreach ($l in $npm) { $locks += "-L"; $locks += $l.FullName }
  if ($locks.Count) { osv-scanner scan $locks --format json --output (Join-Path $out "osv.json") }
  else { osv-scanner scan source -r $Path --format json --output (Join-Path $out "osv.json") }
} else { Write-Host "[osv-scanner] missing -> choco install osv-scanner (or npm audit)" }

if (Get-Command trivy -ErrorAction SilentlyContinue) {
  Write-Host "[trivy] running (vuln+secret+misconfig)"
  trivy fs --scanners vuln,secret,misconfig --format sarif -o (Join-Path $out "trivy.sarif") $Path
} else { Write-Host "[trivy] optional, missing" }

if ((Get-Command bash -ErrorAction SilentlyContinue) -and (bash -lc "command -v ubs" 2>$null)) {
  Write-Host "[ubs] running (logic bug patterns)"
  bash -lc "ubs '$Path' --format=json" > (Join-Path $out "ubs.json")
} else { Write-Host "[ubs] optional, missing" }

if ($ApiUrl) {
  if (Get-Command schemathesis -ErrorAction SilentlyContinue) {
    Write-Host "[schemathesis] fuzzing $ApiUrl"
    # only real-bug checks: 5xx + response schema; skips "undocumented status" / "rejected" noise
    schemathesis run $ApiUrl -c not_a_server_error,response_schema_conformance `
      --exclude-path-regex $ExcludePaths *> (Join-Path $out "schemathesis.txt")
  } else { Write-Host "[schemathesis] missing -> python -m uv tool install schemathesis --python 3.12" }
}

Write-Host "done -> $out"
