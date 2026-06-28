[CmdletBinding()]
param(
    [string]$Version,
    [string]$PrevVersion = "v0.3.0",
    [switch]$Edit  # update an existing release's notes instead of creating it (no asset upload)
)

$ErrorActionPreference = "Stop"

if (-not $Version) {
    throw "Version parameter is required. Example: pwsh -File scripts/gh_release.ps1 -Version v0.1.1"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$cleanVer = $Version.TrimStart('v')

# Load changelog file
$changelogPath = Join-Path $PSScriptRoot "changelog.txt"
if (-not (Test-Path $changelogPath)) {
    throw "changelog.txt file is missing at $changelogPath"
}
$utf8 = [System.Text.Encoding]::UTF8
$changelogLines = [System.IO.File]::ReadAllLines($changelogPath, $utf8)

# Verify versions exist and extract all logs between Version and PrevVersion (exclusive)
$foundStart = $false
$foundEnd = $false
$extractedLogs = @()

foreach ($line in $changelogLines) {
    if ($line -match "^$Version`:") {
        $foundStart = $true
        $note = $line.Substring($line.IndexOf(':') + 1).Trim()
        if ($note) { $extractedLogs += $note }
        continue
    }
    
    if ($foundStart) {
        if ($line -match "^$PrevVersion`:") {
            $foundEnd = $true
            break
        }
        $extractedLogs += $line
    }
}

if (-not $foundStart) {
    throw "Target version $Version is not documented in scripts/changelog.txt."
}
if (-not $foundEnd) {
    throw "Previous version $PrevVersion is not documented in scripts/changelog.txt."
}

$targetChangelog = $extractedLogs -join "`r`n"

$notes = "## Clustara v" + $cleanVer + "`r`n`r`n"
$notes += [regex]::Unescape("### \uc8fc\uc694 \ubcc0\uacbd \uc0ac\ud56d`r`n")
$notes += $targetChangelog + "`r`n`r`n"

$notes += [regex]::Unescape("### \ubc30\ud3ec \ud30c\uc77c`r`n")
$notes += [regex]::Unescape("| \ud30c\uc77c | \uc124\uba85 |`r`n")
$notes += "|------|------|`r`n"
$notes += "| clustara-v" + $cleanVer + [regex]::Unescape(".tar.gz | Docker \uc774\ubbf8\uc9c0 \ud328\ud0a4\uc9c0 (linux/amd64) |`r`n")
$notes += "| clustara-v" + $cleanVer + [regex]::Unescape(".tar.gz.sha256 | SHA256 \uccb4\ud06c\uc12c |`r`n")
$notes += "| README-offline-v" + $cleanVer + [regex]::Unescape(".md | \uc624\ud504\ub77c\uc778 \ubc30\ud3ec \uac00\uc774\ub4dc |`r`n")
$notes += [regex]::Unescape("| Clustara_Report.pdf | Clustara \uae30\ub2a5\u00b7\uc5ed\ud560 \ubc0f \ube44\uc988\ub2c8\uc2a4 \uac00\uce58 \uc885\ud569 \ubcf4\uace0\uc11c |`r`n`r`n")

$notes += [regex]::Unescape("### \ube60\ub978 \uc2dc\uc791`r`n")
$notes += '```' + "bash`r`n"
$notes += [regex]::Unescape("# \uc774\ubbf8\uc9c0 \ub85c\ub4dc`r`n")
$notes += "gunzip -c clustara-" + $Version + ".tar.gz | docker load`r`n`n"
$notes += [regex]::Unescape("# \uc2e4\ud589`r`n")
$notes += "docker run -d --name clustara --restart=always \`r`n"
$notes += "  -p 9090:9090 \`r`n"
$notes += "  -v /opt/clustara/data:/data \`n"
$notes += "  -e UPSTREAM_BASE_URL=https://api.openai.com \`n"
$notes += "  -e UPSTREAM_API_KEY=sk-... \`n"
$notes += "  -e ADMIN_TOKEN=change-me \`n"
$notes += "  clustara:" + $Version + "`r`n"
$notes += '```'

$notesPath = Join-Path $repoRoot "release\release-notes.txt"
# Ensure the release directory exists
$releaseDir = Split-Path -Parent $notesPath
if (-not (Test-Path $releaseDir)) {
    New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
}

# Write as UTF-8 WITHOUT BOM via .NET so the GitHub release body has no leading BOM
# and is identical regardless of which PowerShell edition runs this script.
[System.IO.File]::WriteAllText($notesPath, $notes, (New-Object System.Text.UTF8Encoding($false)))

$assets = @(
    "release\clustara-$Version.tar.gz",
    "release\clustara-$Version.tar.gz.sha256",
    "release\README-offline-$Version.md"
)
$reportPath = "release\Clustara_Report.pdf"
if (Test-Path $reportPath) {
    $assets += $reportPath
}

if ($Edit) {
    # Re-publish corrected notes for an already-created release (no asset re-upload).
    gh release edit $Version --repo hkjang/clustara --notes-file $notesPath
} else {
    gh release create $Version $assets --repo hkjang/clustara --title "$Version - Clustara" --notes-file $notesPath
}

Remove-Item $notesPath -ErrorAction SilentlyContinue
