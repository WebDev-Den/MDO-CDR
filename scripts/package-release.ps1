#Requires -Version 7.0

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$taskRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskBuildRoot = Join-Path $taskRoot 'target/release'
$taskOutputRoot = Join-Path $taskRoot 'dist-packages'

$taskRustc = Get-Command rustc -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $taskRustc) {
    throw 'rustc was not found on PATH. Install Rust, then build with: cargo build --release --locked --lib --bin mdocdr'
}
$taskRustInfo = & $taskRustc.Source -vV
if ($LASTEXITCODE -ne 0) { throw 'Could not determine the Rust compiler host with rustc -vV.' }
$taskHostLine = @($taskRustInfo | Where-Object { $_ -match '^host: ' })
if ($taskHostLine.Count -ne 1) { throw 'rustc -vV did not report exactly one host target.' }
$taskHostTriple = $taskHostLine[0].Substring(6).Trim()
if ($taskHostTriple -notmatch '^[a-zA-Z0-9_-]+$') { throw 'rustc reported an invalid host target.' }

if ($IsWindows -and $taskHostTriple -like '*-pc-windows-msvc') {
    $taskExecutable = 'mdocdr.exe'
    $taskLibraries = @('mdo_cdr.dll', 'mdo_cdr.lib')
    $taskArchiveExtension = '.zip'
} elseif ($IsLinux -and $taskHostTriple -like '*-linux-*') {
    $taskExecutable = 'mdocdr'
    $taskLibraries = @('libmdo_cdr.so', 'libmdo_cdr.a')
    $taskArchiveExtension = '.tar.gz'
} elseif ($IsMacOS -and $taskHostTriple -like '*-apple-darwin') {
    $taskExecutable = 'mdocdr'
    $taskLibraries = @('libmdo_cdr.dylib', 'libmdo_cdr.a')
    $taskArchiveExtension = '.tar.gz'
} else {
    throw "Unsupported native packaging host: $taskHostTriple. Use Windows MSVC, Linux, or macOS with its native Rust toolchain."
}

$taskFiles = @(
    @{ Source = Join-Path $taskBuildRoot $taskExecutable; Destination = "bin/$taskExecutable" }
    @{ Source = Join-Path $taskRoot 'README.md'; Destination = 'README.md' }
    @{ Source = Join-Path $taskRoot 'LICENSE'; Destination = 'LICENSE' }
)
foreach ($taskLibrary in $taskLibraries) {
    $taskFiles += @{ Source = Join-Path $taskBuildRoot $taskLibrary; Destination = "lib/$taskLibrary" }
}
if ($IsWindows) {
    foreach ($taskLauncher in @('Start.cmd', 'Start.ps1')) {
        $taskFiles += @{ Source = Join-Path $taskRoot $taskLauncher; Destination = $taskLauncher }
    }
    $taskImportLibrary = Join-Path $taskBuildRoot 'mdo_cdr.dll.lib'
    if (Test-Path -LiteralPath $taskImportLibrary -PathType Leaf) {
        $taskFiles += @{ Source = $taskImportLibrary; Destination = 'lib/mdo_cdr.dll.lib' }
    }
}

foreach ($taskFile in $taskFiles) {
    if (-not (Test-Path -LiteralPath $taskFile.Source -PathType Leaf)) {
        throw "Required package file is missing: $($taskFile.Source). Run cargo build --release --locked --lib --bin mdocdr from the repository root."
    }
    if ((Get-Item -LiteralPath $taskFile.Source).Length -eq 0) {
        throw "Required package file is empty: $($taskFile.Source). Rebuild before packaging."
    }
}
if (-not $IsWindows) {
    foreach ($taskUtility in @('tar', 'chmod')) {
        if ($null -eq (Get-Command $taskUtility -CommandType Application -ErrorAction SilentlyContinue)) {
            throw "Required packaging utility is missing: $taskUtility. Install it and retry."
        }
    }
}

$taskArchiveName = "MDO-CDR-$taskHostTriple$taskArchiveExtension"
$taskArchivePath = Join-Path $taskOutputRoot $taskArchiveName
$taskChecksumPath = "$taskArchivePath.sha256"
foreach ($taskDestination in @($taskArchivePath, $taskChecksumPath)) {
    if (Test-Path -LiteralPath $taskDestination) {
        throw "Package output already exists: $taskDestination. Move or remove that generated file before packaging again."
    }
}

[void][System.IO.Directory]::CreateDirectory($taskOutputRoot)
$taskStageRoot = Join-Path $taskOutputRoot ("staging-" + [guid]::NewGuid().ToString('N'))
$taskPackageRoot = Join-Path $taskStageRoot 'MDO-CDR'
[void][System.IO.Directory]::CreateDirectory((Join-Path $taskPackageRoot 'bin'))
[void][System.IO.Directory]::CreateDirectory((Join-Path $taskPackageRoot 'lib'))
foreach ($taskFile in $taskFiles) {
    Copy-Item -LiteralPath $taskFile.Source -Destination (Join-Path $taskPackageRoot $taskFile.Destination)
}
if (-not $IsWindows) {
    & chmod 755 (Join-Path $taskPackageRoot "bin/$taskExecutable")
    if ($LASTEXITCODE -ne 0) { throw 'Could not set the packaged executable permission.' }
}

$taskHashLines = @(Get-ChildItem -LiteralPath $taskPackageRoot -File -Recurse | Sort-Object FullName | ForEach-Object {
    $taskRelativePath = [System.IO.Path]::GetRelativePath($taskPackageRoot, $_.FullName).Replace('\', '/')
    $taskHash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$taskHash  $taskRelativePath"
})
$taskUtf8 = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText((Join-Path $taskPackageRoot 'SHA256SUMS'), ($taskHashLines -join "`n") + "`n", $taskUtf8)

if ($IsWindows) {
    Compress-Archive -LiteralPath $taskPackageRoot -DestinationPath $taskArchivePath -CompressionLevel Optimal
} else {
    & tar -czf $taskArchivePath -C $taskStageRoot 'MDO-CDR'
    if ($LASTEXITCODE -ne 0) { throw "Creating the release archive failed. Staged files remain at $taskStageRoot" }
}
if (-not (Test-Path -LiteralPath $taskArchivePath -PathType Leaf) -or (Get-Item -LiteralPath $taskArchivePath).Length -eq 0) {
    throw "The release archive was not created successfully. Staged files remain at $taskStageRoot"
}
$taskArchiveHash = (Get-FileHash -LiteralPath $taskArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText($taskChecksumPath, "$taskArchiveHash  $taskArchiveName`n", $taskUtf8)
Write-Output $taskArchivePath
