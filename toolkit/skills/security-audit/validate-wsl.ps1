# Runs validate-findings.cjs or validate-coverage-ledger.cjs under Node inside WSL.
#
# Why: Windows Node has no O_NOFOLLOW, so the validators refuse every input there (by design: they fail closed).
# Linux has it, so the same unmodified validators run correctly in WSL.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File <skill-dir>\validate-wsl.ps1 findings <output-dir>\findings.json
#   powershell -ExecutionPolicy Bypass -File <skill-dir>\validate-wsl.ps1 ledger   <output-dir>\coverage-ledger.json
#
# Exit codes: the validator's own (0 = valid, 1 = invalid), 2 = setup problem (no WSL, no Node, no input file),
# 3 = the validator printed no PASS or FAIL line, so the result is unknown and must not count as valid.
#
# Needs: WSL with a distro (default "Ubuntu") and Node at $HOME/.local/node/bin/node inside it.
# Override with VALIDATE_WSL_DISTRO and VALIDATE_WSL_NODE (an absolute path inside WSL).
#
# Arguments go to wsl.exe with --exec, so no shell parses them (no quoting or injection problems).
param(
    [Parameter(Mandatory = $true, Position = 0)][ValidateSet('findings', 'ledger')][string]$Kind,
    [Parameter(Mandatory = $true, Position = 1)][string]$Path
)

$ErrorActionPreference = 'Stop'

$distro = if ($env:VALIDATE_WSL_DISTRO) { $env:VALIDATE_WSL_DISTRO } else { 'Ubuntu' }

function ConvertTo-WslPath([string]$WindowsPath) {
    $full = [System.IO.Path]::GetFullPath($WindowsPath)
    $drive = $full.Substring(0, 1).ToLowerInvariant()
    return '/mnt/' + $drive + ($full.Substring(2) -replace '\\', '/')
}

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    [Console]::Error.WriteLine("input not found: $Path")
    exit 2
}

$wslHome = (& wsl.exe -d $distro --exec printenv HOME 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $wslHome) {
    [Console]::Error.WriteLine("WSL distro '$distro' is not available. Install it with: wsl --install -d Ubuntu")
    exit 2
}
$node = if ($env:VALIDATE_WSL_NODE) { $env:VALIDATE_WSL_NODE } else { "$wslHome/.local/node/bin/node" }
& wsl.exe -d $distro --exec test -x $node
if ($LASTEXITCODE -ne 0) {
    [Console]::Error.WriteLine("Node not found in WSL at $node. Install Node 24 there (see docs/USING.md), or set VALIDATE_WSL_NODE.")
    exit 2
}

$script = if ($Kind -eq 'findings') { 'validate-findings.cjs' } else { 'validate-coverage-ledger.cjs' }
$skillDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$wslScript = ConvertTo-WslPath (Join-Path $skillDir $script)
$wslInput = ConvertTo-WslPath (Resolve-Path -LiteralPath $Path).Path

$ErrorActionPreference = 'Continue'
$output = (& wsl.exe -d $distro --exec $node $wslScript $wslInput 2>&1 | Out-String)
$code = $LASTEXITCODE
Write-Output $output.TrimEnd()

if ($code -eq 0 -and $output -notmatch '(?m)^PASS:') {
    [Console]::Error.WriteLine('validator printed no PASS line; the result is unknown and must not count as valid')
    exit 3
}
exit $code
