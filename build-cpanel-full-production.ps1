#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build the clean, full-production cPanel release package for SRP.

.DESCRIPTION
    Produces one zip laid out for a cPanel account whose main domain docroot is
    public_html:

        <zip>/public_html/          <- main domain DocumentRoot
            .htaccess               <- host routing for gen./s./r./wildcard
            index.php 404.php env.php ...
            assets/  public/  statistics/  redirect/
            vendor/                 <- composer --no-dev, pre-optimised
            migrations/ schema.sql .env.example ...

    The application root IS the DocumentRoot. The root .htaccess resolves hosts
    by probing %{DOCUMENT_ROOT}/public, /statistics and /redirect, so
    gen.<domain>, s.<domain>, r.<domain> and every wildcard tracker host are all
    served from this one docroot. No per-subdomain DocumentRoot is required.

    Use -DocrootWrapper '' (or '.') for the flat variant instead: identical
    contents with no public_html/ prefix, for installs that extract into the
    account home (e.g. ~/yourdomain.com) and point each subdomain at
    <root>/public, <root>/statistics, <root>/redirect as INSTALL.md section B
    describes.

    Packaging is fail-closed:

      1. Root-entry allowlist. Only the files and directories named in
         $AllowFiles / $AllowDirs are considered, so a newly added dev artefact
         cannot leak into a release just by existing on disk.
      2. Always-deny list for secrets and generated state (.env, install.token,
         install.lock, .user.ini, report_auth.php, repass.php, logs, archives).
         This is applied while copying AND re-checked against the finished zip.
         If a denied entry survives, the zip is deleted and the build fails.
      3. Required-entry assertion. If a critical runtime file is missing the zip
         is deleted and the build fails.
      4. Optional PHP lint of every packaged .php file, when a php binary is on
         PATH.

.PARAMETER OutputPath
    Destination zip. Relative paths resolve against the current directory.
    Default: srp-full-production-cpanel.zip

.PARAMETER DocrootWrapper
    Directory to nest the tree under inside the zip. Default: public_html.
    Pass '' or '.' for the flat (no-prefix) layout.

.PARAMETER Compression
    Zip compression level. Default: Optimal.

.PARAMETER SyntaxCheck
    Run `php -l` over every packaged .php file. Skipped with a warning when no
    php binary is on PATH. Default: on.

.EXAMPLE
    pwsh ./build-cpanel-full-production.ps1

.EXAMPLE
    pwsh ./build-cpanel-full-production.ps1 -DocrootWrapper '' -OutputPath srp-flat-cpanel.zip
#>
[CmdletBinding()]
param(
    [string] $OutputPath = 'srp-full-production-cpanel.zip',
    [string] $DocrootWrapper = 'public_html',
    [ValidateSet('Optimal', 'Fastest', 'NoCompression')]
    [string] $Compression = 'Optimal',
    [bool] $SyntaxCheck = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Repository root (directory holding this script) ────────────────────────────
$RepoRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Get-Location).Path
}

# ── Packaging policy ──────────────────────────────────────────────────────────

# Root files that belong in a production release.
$AllowFiles = @(
    '.env.example'          # INSTALL.md section B step 3: `cp .env.example .env`
    '.htaccess'             # host-based subdomain routing; without it nothing routes
    '404.php'
    'INSTALL.md'
    'README.md'
    'asset_url.php'
    'Base64URL.php'
    'cleanup-storage.php'
    'composer.json'
    'composer.lock'
    'connection_pdo.php'
    'deploy-production.sh'
    'domain_readiness.php'
    'env.php'
    'favicon.ico'
    'health.php'
    'imgp_handler.php'
    'index.php'
    'inode-snapshot.sh'
    'install-sh.txt'
    'ip_address.php'
    'legal.php'
    'login_throttle.php'
    'logo.svg'
    'robots.php'
    'robots.txt'
    'rotate-logs.sh'
    'schema.sql'
    'setup-cron.sh'
    'sitemap.php'
)

# Root directories that belong in a production release.
# Composer installs --no-dev, so vendor/ ships production dependencies only.
$AllowDirs = @(
    'assets'
    'migrations'            # CLI-only upgrade scripts, blocked over HTTP by .htaccess
    'public'
    'redirect'
    'statistics'
    'vendor'
)

# Never ship these, regardless of where they appear. Matched against the
# source-relative path with forward slashes.
#
# Deliberately NOT listed: *.sql. schema.sql is a required release file, and the
# allowlist already prevents any other .sql dump from being picked up.
$DenyPatterns = @(
    '(^|/)\.env$'                       # live credentials
    '(^|/)\.env\.(?!example$)'          # .env.local, .env.production, .env.bak
    '(^|/)install\.token$'              # installer pre-shared secret
    '(^|/)install\.lock$'               # completed-install marker
    '(^|/)\.user\.ini$'                 # per-account error_log path
    '(^|/)report_auth\.php$'            # generated statistics credential
    '(^|/)repass\.php$'                 # generated statistics admin hash
    '\.log$'
    '(^|/)error_log$'
    '(^|/)logs/'                        # redirect/logs/ runtime cache + logs
    '\.(zip|rar|7z|tar|tgz|gz|bz2|bak|old|orig|swp|dump)$'
    '(^|/)\.(git|continue|vscode|github)($|/)'
    '(^|/)\.DS_Store$'
    '(^|/)Thumbs\.db$'
    '(^|/)desktop\.ini$'
    '~$'
)

# Assets that must exist in the finished zip, or the build is a failure.
$RequiredEntries = @(
    '.htaccess'
    'index.php'
    'env.php'
    'connection_pdo.php'
    'schema.sql'
    '.env.example'
    'health.php'
    'vendor/autoload.php'
    'public/index.php'
    'public/login.php'
    'public/install.php'
    'statistics/index.php'
    'statistics/login.php'
    'redirect/index.php'
    'redirect/shorten-web.php'
)

$DenyRegex = [regex]::new(
    '(' + ($DenyPatterns -join '|') + ')',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

# ── Resolve output paths ──────────────────────────────────────────────────────
$ZipPath = if ([System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath
} else {
    Join-Path (Get-Location).Path $OutputPath
}
$ZipPath = [System.IO.Path]::GetFullPath($ZipPath)
$ManifestPath = [System.IO.Path]::ChangeExtension($ZipPath, '.manifest.txt')

$Prefix = if ([string]::IsNullOrWhiteSpace($DocrootWrapper) -or $DocrootWrapper -eq '.') {
    ''
} else {
    $DocrootWrapper.Trim('/', '\') + '/'
}

# ── Collect allowlisted items ─────────────────────────────────────────────────
$Items = [System.Collections.Generic.List[object]]::new()
$Denied = [System.Collections.Generic.List[string]]::new()
$MissingAllow = [System.Collections.Generic.List[string]]::new()

function Add-Item {
    param([string] $Rel, [string] $Full, [bool] $IsDir)

    if ($DenyRegex.IsMatch($Rel)) {
        $Denied.Add($Rel)
        return
    }
    $Items.Add([pscustomobject]@{ Rel = $Rel; Full = $Full; IsDir = $IsDir })
}

foreach ($name in $AllowFiles) {
    $full = Join-Path $RepoRoot $name
    if (Test-Path -LiteralPath $full -PathType Leaf) {
        Add-Item -Rel $name -Full $full -IsDir $false
    } else {
        $MissingAllow.Add($name)
    }
}

foreach ($name in $AllowDirs) {
    $full = Join-Path $RepoRoot $name
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        $MissingAllow.Add("$name/")
        continue
    }

    Add-Item -Rel "$name/" -Full $full -IsDir $true

    foreach ($child in Get-ChildItem -LiteralPath $full -Recurse -Force) {
        $rel = [System.IO.Path]::GetRelativePath($RepoRoot, $child.FullName).Replace('\', '/')
        if ($child.PSIsContainer) {
            Add-Item -Rel "$rel/" -Full $child.FullName -IsDir $true
        } else {
            Add-Item -Rel $rel -Full $child.FullName -IsDir $false
        }
    }
}

# Root entries present on disk but intentionally left out of the release.
$ShippedTop = @($AllowFiles) + ($AllowDirs | ForEach-Object { "$_/" })
$SkippedTop = Get-ChildItem -LiteralPath $RepoRoot -Force |
    Where-Object { $ShippedTop -notcontains $_.Name -and $ShippedTop -notcontains "$($_.Name)/" } |
    ForEach-Object { if ($_.PSIsContainer) { "$($_.Name)/" } else { $_.Name } } |
    Sort-Object

$Ordered = $Items | Sort-Object -Property Rel -Unique

if ($Ordered.Count -eq 0) {
    throw "Nothing to package - allowlist matched no files under $RepoRoot"
}

# ── Write the zip ─────────────────────────────────────────────────────────────
Add-Type -AssemblyName System.IO.Compression | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null

$ZipDir = Split-Path -Parent $ZipPath
if (-not (Test-Path -LiteralPath $ZipDir)) {
    New-Item -ItemType Directory -Path $ZipDir -Force | Out-Null
}
if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
if (Test-Path -LiteralPath $ManifestPath) { Remove-Item -LiteralPath $ManifestPath -Force }

$Level = [System.IO.Compression.CompressionLevel]::$Compression

$FileStream = [System.IO.File]::Open($ZipPath, [System.IO.FileMode]::CreateNew)
$Zip = [System.IO.Compression.ZipArchive]::new(
    $FileStream,
    [System.IO.Compression.ZipArchiveMode]::Create,
    $false
)

try {
    foreach ($item in $Ordered) {
        $entryName = $Prefix + $item.Rel
        $entry = $Zip.CreateEntry($entryName, $Level)
        $entry.LastWriteTime = (Get-Item -LiteralPath $item.Full).LastWriteTime

        if ($item.IsDir) { continue }

        $outStream = $entry.Open()
        try {
            $inStream = [System.IO.File]::OpenRead($item.Full)
            try { $inStream.CopyTo($outStream) } finally { $inStream.Dispose() }
        } finally {
            $outStream.Dispose()
        }
    }
} finally {
    $Zip.Dispose()
    $FileStream.Dispose()
}

# ── Verify the finished zip ───────────────────────────────────────────────────
$Fail = [System.Collections.Generic.List[string]]::new()

$Verify = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
try {
    $Entries = @()
    foreach ($e in $Verify.Entries) {
        $n = $e.FullName
        if ($Prefix -and $n.StartsWith($Prefix, [StringComparison]::Ordinal)) {
            $n = $n.Substring($Prefix.Length)
        }
        $Entries += [pscustomobject]@{ Name = $n; Length = $e.Length }
    }

    $Leaked = @($Entries | Where-Object { $_.Name -and $DenyRegex.IsMatch($_.Name) } |
        ForEach-Object { $_.Name })
    foreach ($l in $Leaked) { $Fail.Add("denied entry survived: $l") }

    $Names = @{}
    foreach ($e in $Entries) { $Names[$e.Name] = $true }
    foreach ($req in $RequiredEntries) {
        if (-not $Names.ContainsKey($req)) { $Fail.Add("required entry missing: $req") }
    }

    # Zero-byte files are legitimate only for .gitkeep dir placeholders.
    $ZeroByte = @($Entries | Where-Object {
            $_.Length -eq 0 -and -not $_.Name.EndsWith('/') -and
            [System.IO.Path]::GetFileName($_.Name) -ne '.gitkeep'
        } | ForEach-Object { $_.Name })
} finally {
    $Verify.Dispose()
}

if ($Fail.Count -gt 0) {
    Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host 'BUILD FAILED - zip deleted:' -ForegroundColor Red
    $Fail | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}

# ── Optional PHP lint of packaged sources ─────────────────────────────────────
$LintResult = 'skipped (no php binary on PATH)'
$PhpBin = Get-Command php -ErrorAction SilentlyContinue
if ($SyntaxCheck -and $PhpBin) {
    $Targets = @($Ordered | Where-Object { -not $_.IsDir -and $_.Rel -match '\.php$' })
    $LintErrors = @()
    foreach ($t in $Targets) {
        $out = & $PhpBin.Source -l $t.Full 2>&1
        if ($LASTEXITCODE -ne 0) {
            $LintErrors += "$($t.Rel): $($out -join ' ')"
        }
    }
    if ($LintErrors.Count -gt 0) {
        Write-Host ''
        Write-Host "PHP LINT FAILED ($($LintErrors.Count) file(s)):" -ForegroundColor Red
        $LintErrors | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        exit 1
    }
    $LintResult = "$($Targets.Count) file(s) OK"
} elseif ($SyntaxCheck -and -not $PhpBin) {
    Write-Host 'WARNING: php not found on PATH - skipping syntax check.' -ForegroundColor Yellow
}

# ── Summary ───────────────────────────────────────────────────────────────────
$ZipInfo = Get-Item -LiteralPath $ZipPath
$Sha = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash
$DirCount = @($Ordered | Where-Object { $_.IsDir }).Count
$FileCount = @($Ordered | Where-Object { -not $_.IsDir }).Count

$RawBytes = 0
foreach ($f in $Ordered) {
    if (-not $f.IsDir) { $RawBytes += (Get-Item -LiteralPath $f.Full).Length }
}

$SizeLine = 'size         : {0:N2} MB zipped from {1:N2} MB raw' -f ($ZipInfo.Length / 1MB), ($RawBytes / 1MB)

$Summary = [System.Collections.Generic.List[string]]::new()
$Summary.Add("SRP full-production cPanel package")
$Summary.Add("built        : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
$Summary.Add("source       : $RepoRoot")
$Summary.Add("zip          : $ZipPath")
$Summary.Add("sha256       : $Sha")
$Summary.Add("layout       : $(if ($Prefix) { "$Prefix* (main domain docroot)" } else { 'flat - extract into account root' })")
$Summary.Add("entries      : $FileCount file(s), $DirCount dir(s)")
$Summary.Add($SizeLine)
$Summary.Add("compression  : $Compression")
$Summary.Add("php lint     : $LintResult")
$Summary.Add("")
$Summary.Add("Excluded root entries: " + ($SkippedTop -join ', '))
if ($Denied.Count -gt 0) {
    $Summary.Add("Excluded secrets/state: " + (($Denied | Sort-Object -Unique) -join ', '))
}
if ($MissingAllow.Count -gt 0) {
    $Summary.Add("Allowlisted but absent: " + (($MissingAllow | Sort-Object -Unique) -join ', '))
}
if ($ZeroByte.Count -gt 0) {
    $Summary.Add("WARNING zero-byte files: " + ($ZeroByte -join ', '))
}
$Summary.Add("")
$Summary.Add("After extracting, apply permissions from INSTALL.md section B step 0:")
$Summary.Add("  find . -type d -exec chmod 750 {} \;")
$Summary.Add("  find . -type f -exec chmod 640 {} \;")
$Summary.Add("  chmod 750 deploy-production.sh setup-cron.sh rotate-logs.sh inode-snapshot.sh")
$Summary.Add("Zip files carry no Unix mode bits, so this step is mandatory.")

$Summary | ForEach-Object { Write-Host $_ }
$Summary | Set-Content -LiteralPath $ManifestPath -Encoding utf8

Write-Host ''
Write-Host "Manifest: $ManifestPath"
Write-Host 'RESULT: OK' -ForegroundColor Green
exit 0
