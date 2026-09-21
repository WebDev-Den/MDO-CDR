param(
    [switch]$DryRun,
    [switch]$AllowDirty,
    [int]$IndexSettleSeconds = 45
)

$ErrorActionPreference = "Stop"

$leafCrates = @(
    "defender-core",
    "defender-ffi",
    "defender-handlers-media",
    "defender-observability",
    "defender-signatures"
)
$rootCrate = "mdo_cdr"

function Invoke-Cargo {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "cargo $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

$metadata = & cargo metadata --format-version 1 --no-deps | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "cargo metadata --format-version 1 --no-deps failed with exit code $LASTEXITCODE"
}

$crateVersions = @{}
foreach ($package in $metadata.packages) {
    $crateVersions[$package.name] = $package.version
}

function Test-CrateVersionPublished {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Crate
    )

    $version = $crateVersions[$Crate]
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "Could not determine workspace version for crate '$Crate'."
    }

    $uri = "https://crates.io/api/v1/crates/$Crate/$version"
    $request = @{
        Method = "Get"
        Uri = $uri
    }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $request.UseBasicParsing = $true
    }

    try {
        $null = Invoke-WebRequest @request
        return $true
    } catch {
        $response = $_.Exception.Response
        $statusCode = $null
        if ($null -ne $response) {
            try {
                $statusCode = [int]$response.StatusCode
            } catch {
                $statusCode = $response.StatusCode.value__
            }
        }
        if ($statusCode -eq 404) {
            return $false
        }
        throw
    }
}

$dirtyArgs = @()
if ($AllowDirty) {
    $dirtyArgs += "--allow-dirty"
}

if ($DryRun) {
    Write-Host "Running publish preflight for workspace crates..."
    Invoke-Cargo -Arguments (@("package", "--workspace") + $dirtyArgs)
    foreach ($crate in $leafCrates) {
        Invoke-Cargo -Arguments (@("publish", "--dry-run", "-p", $crate) + $dirtyArgs)
    }
    Write-Host "Skipping cargo publish --dry-run for $rootCrate because its internal workspace"
    Write-Host "dependencies are not yet present on crates.io before the first live release."
    Write-Host "cargo package --workspace already verified the root tarball against a local temp registry."
    exit 0
}

if ([string]::IsNullOrWhiteSpace($env:CARGO_REGISTRY_TOKEN)) {
    throw "CARGO_REGISTRY_TOKEN must be set for live publish."
}

foreach ($crate in $leafCrates) {
    if (Test-CrateVersionPublished -Crate $crate) {
        Write-Host "Skipping $crate $($crateVersions[$crate]) because it is already published."
        continue
    }
    Write-Host "Publishing $crate..."
    Invoke-Cargo -Arguments (@("publish", "-p", $crate) + $dirtyArgs)
    if ($IndexSettleSeconds -gt 0) {
        Write-Host "Waiting $IndexSettleSeconds seconds for crates.io index propagation..."
        Start-Sleep -Seconds $IndexSettleSeconds
    }
}

if (Test-CrateVersionPublished -Crate $rootCrate) {
    Write-Host "Skipping $rootCrate $($crateVersions[$rootCrate]) because it is already published."
    exit 0
}

Write-Host "Publishing $rootCrate..."
Invoke-Cargo -Arguments (@("publish", "-p", $rootCrate) + $dirtyArgs)
