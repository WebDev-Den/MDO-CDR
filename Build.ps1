param([ValidateSet('Build','Test','Check')][string]$Action = 'Build')
$ErrorActionPreference = 'Stop'
$taskRoot = $PSScriptRoot
$taskRuntime = Join-Path (Split-Path $taskRoot -Parent) '.codex-tmp\soft-rust-runtime'
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    if (-not (Test-Path -LiteralPath (Join-Path $taskRuntime 'cargo\bin\cargo.exe'))) {
        throw 'Rust is required only for rebuilding. Install it from https://rustup.rs, or use Start.cmd with the prepared binary.'
    }
    $env:CARGO_HOME = Join-Path $taskRuntime 'cargo'
    $env:RUSTUP_HOME = Join-Path $taskRuntime 'rustup'
    $env:PATH = "$env:CARGO_HOME\bin;$env:PATH"
}
$env:CARGO_TARGET_DIR = Join-Path $taskRoot 'target'
Push-Location -LiteralPath $taskRoot
try {
    switch ($Action) {
        'Test' { & cargo test --workspace --locked; if ($LASTEXITCODE -ne 0) { throw 'Tests failed' } }
        'Check' {
            & cargo fmt --all --check; if ($LASTEXITCODE -ne 0) { throw 'Formatting check failed' }
            & cargo clippy --workspace --all-targets --locked -- -D warnings; if ($LASTEXITCODE -ne 0) { throw 'Code check failed' }
        }
        'Build' {
            & cargo build --release --locked --bin mdocdr; if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
            New-Item -ItemType Directory -Path (Join-Path $taskRoot 'bin') -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $taskRoot 'target\release\mdocdr.exe') -Destination (Join-Path $taskRoot 'bin\mdocdr.exe')
            & (Join-Path $taskRoot 'bin\mdocdr.exe') --self-test
            if ($LASTEXITCODE -ne 0) { throw 'Executable self-test failed' }
        }
    }
} finally { Pop-Location }
