# PenPard pre-commit hook (PowerShell)
# Blocks commits containing sensitive file types or secret-like patterns.
#
# Usage: called automatically by git if hooksPath is set.
# Install:
#   Copy-Item .githooks\pre-commit.ps1 .git\hooks\pre-commit.ps1
#   git config core.hooksPath .githooks
#
# Note: On Windows, git may need "pre-commit" (no extension) wrapping this.
# See .githooks\pre-commit (bash) which calls this script on Windows.

$ERRORS = 0

$BLOCKED_EXTENSIONS = @(
    "\.pdf$", "\.docx?$", "\.har$", "\.pcap$", "\.pcapng$", "\.cap$",
    "\.pem$", "\.key$", "\.p12$", "\.pfx$",
    "\.sqlite$", "\.sqlite3$", "\.db$", "\.env$"
)

$SECRET_PATTERNS = @(
    "Authorization:\s*Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    "api[_\-]?key\s*[:=]\s*[`'`"][A-Za-z0-9]{20,}",
    "client_secret\s*[:=]\s*[`'`"][A-Za-z0-9]{12,}",
    "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
)

$SENSITIVE_DIRS = @("backend/uploads", "backend/logs", "reports/", "samples/")

# Staged files
$staged = git diff --cached --name-only --diff-filter=ACM 2>&1

foreach ($pattern in $BLOCKED_EXTENSIONS) {
    $matches = $staged | Where-Object { $_ -match $pattern }
    if ($matches) {
        Write-Host "[pre-commit] BLOCKED: Sensitive file type detected:" -ForegroundColor Red
        $matches | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        $ERRORS++
    }
}

# Check staged content for secrets
$diff = git diff --cached -U0 2>&1
$addedLines = $diff | Where-Object { $_ -match "^\+" -and $_ -notmatch "^\+\+\+" }

foreach ($pattern in $SECRET_PATTERNS) {
    $matches = $addedLines | Where-Object { $_ -match $pattern }
    if ($matches) {
        Write-Host "[pre-commit] BLOCKED: Secret-like pattern in staged content:" -ForegroundColor Red
        Write-Host "  Pattern: $pattern" -ForegroundColor Yellow
        $matches | Select-Object -First 3 | ForEach-Object { Write-Host "  $_" }
        $ERRORS++
    }
}

foreach ($dir in $SENSITIVE_DIRS) {
    $matches = $staged | Where-Object { $_ -match "^$([regex]::Escape($dir))" }
    if ($matches) {
        Write-Host "[pre-commit] BLOCKED: File from sensitive directory:" -ForegroundColor Red
        $matches | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        $ERRORS++
    }
}

if ($ERRORS -gt 0) {
    Write-Host ""
    Write-Host "COMMIT BLOCKED: $ERRORS sensitive item(s) detected." -ForegroundColor Red
    Write-Host "Remove the files/patterns, see SECURITY.md for guidance." -ForegroundColor Red
    exit 1
}

Write-Host "[pre-commit] Security check passed." -ForegroundColor Green
exit 0
