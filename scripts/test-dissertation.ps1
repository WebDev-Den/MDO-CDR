#Requires -Version 7.0
param([string]$RunName = ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')))

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest
if ($RunName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
    throw 'RunName must contain only letters, digits, dots, underscores and hyphens.'
}
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskRunDirectory = Join-Path $taskRoot "validation/runs/$RunName"
if (Test-Path -LiteralPath $taskRunDirectory) { throw "Run already exists: $taskRunDirectory" }

if ($null -eq (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $taskRuntime = Join-Path (Split-Path $taskRoot -Parent) '.codex-tmp/soft-rust-runtime'
    if (-not (Test-Path -LiteralPath (Join-Path $taskRuntime 'cargo/bin/cargo.exe'))) {
        throw 'Install Rust/Cargo and add them to PATH.'
    }
    $env:CARGO_HOME = Join-Path $taskRuntime 'cargo'
    $env:RUSTUP_HOME = Join-Path $taskRuntime 'rustup'
    $env:PATH = "$env:CARGO_HOME/bin$([IO.Path]::PathSeparator)$env:PATH"
}
foreach ($taskVariable in @('MDO_TEST_FFMPEG', 'MDO_TEST_FFPROBE')) {
    $taskValue = [Environment]::GetEnvironmentVariable($taskVariable)
    if ([string]::IsNullOrWhiteSpace($taskValue) -or $null -eq (Get-Command $taskValue -CommandType Application -ErrorAction SilentlyContinue)) {
        throw "Set $taskVariable to an installed executable before running the complete series."
    }
}
$env:CARGO_TERM_COLOR = 'never'
$env:RUST_BACKTRACE = '1'
$taskUtf8 = [Text.UTF8Encoding]::new($false)
function Write-RunText([string]$Name, [string]$Value) {
    [IO.File]::WriteAllText((Join-Path $taskRunDirectory $Name), $Value.Replace("`r`n", "`n") + "`n", $taskUtf8)
}
function Get-TextHash([string]$Value) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($taskUtf8.GetBytes($Value))).ToLowerInvariant()
}

Push-Location -LiteralPath $taskRoot
try {
    $taskStarted = [DateTime]::UtcNow
    $taskRevision = (& git rev-parse HEAD | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Run from a Git checkout.' }
    $taskDirty = -not [string]::IsNullOrWhiteSpace((& git status --porcelain | Out-String))
    $taskPlan = Get-Content -LiteralPath (Join-Path $taskRoot 'validation/case-plan.json') -Raw | ConvertFrom-Json
    $taskPaths = @(& git ls-files --cached --others --exclude-standard -- src crates tests scripts .github/workflows .gitattributes Cargo.toml Cargo.lock validation/case-plan.json | Select-Object -Unique)
    if ($LASTEXITCODE -ne 0 -or $taskPaths.Count -eq 0) { throw 'Cannot inventory tested sources.' }
    [Array]::Sort($taskPaths, [StringComparer]::Ordinal)
    $taskSources = @($taskPaths | ForEach-Object {
        $taskSourceText = [IO.File]::ReadAllText((Join-Path $taskRoot $_)).Replace("`r`n", "`n")
        [ordered]@{ path = $_; sha256_lf = Get-TextHash $taskSourceText }
    })
    $taskSourceFingerprint = Get-TextHash (($taskSources | ForEach-Object { "$($_.sha256_lf)  $($_.path)" }) -join "`n")
    $taskEnvironment = [ordered]@{
        os = [Runtime.InteropServices.RuntimeInformation]::OSDescription
        architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        logical_processors = [Environment]::ProcessorCount
        powershell = $PSVersionTable.PSVersion.ToString()
        rustc = ((& rustc -Vv) -join "`n")
        cargo = ((& cargo -V) -join "`n")
        ffmpeg = (@(& $env:MDO_TEST_FFMPEG -version)[0])
        ffprobe = (@(& $env:MDO_TEST_FFPROBE -version)[0])
    }
    New-Item -ItemType Directory -Path $taskRunDirectory | Out-Null
    $taskCommands = @(
        @{ name = 'workspace'; args = @('test', '--workspace', '--locked', '--', '--nocapture', '--test-threads=1') }
        @{ name = 'required-reconstruction'; args = @('test', '--locked', '--test', 'reconstruction_levels', 'semantic_audio_and_video_transcode_with_external_runtime', '--', '--ignored', '--exact', '--nocapture') }
        @{ name = 'media-cli'; args = @('test', '--locked', '--test', 'media_cli_contract', 'cli_audio_video_roundtrip_with_external_runtime', '--', '--ignored', '--exact', '--nocapture') }
        @{ name = 'audio-content'; args = @('test', '--locked', '--test', 'dissertation_media', 'audio_content_matches_dissertation_thresholds', '--', '--ignored', '--exact', '--nocapture') }
        @{ name = 'video-content'; args = @('test', '--locked', '--test', 'dissertation_media', 'video_content_matches_dissertation_thresholds', '--', '--ignored', '--exact', '--nocapture') }
    )
    $taskExecutions = [Collections.Generic.List[object]]::new()
    $taskCases = [Collections.Generic.List[object]]::new()
    $taskSchemaErrors = [Collections.Generic.List[string]]::new()
    foreach ($taskCommand in $taskCommands) {
        Write-Host "Running $($taskCommand.name)..."
        $taskWatch = [Diagnostics.Stopwatch]::StartNew()
        $taskArguments = $taskCommand.args
        $taskOutput = @(& cargo @taskArguments 2>&1 | ForEach-Object { "$_" })
        $taskExitCode = $LASTEXITCODE
        $taskWatch.Stop()
        $taskLog = ($taskOutput -join "`n").Replace($taskRoot, '<repository>')
        Write-RunText "$($taskCommand.name).log" $taskLog
        $taskPassed = 0; $taskFailed = 0; $taskIgnored = 0
        foreach ($taskMatch in [regex]::Matches($taskLog, 'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;')) {
            $taskPassed += [int]$taskMatch.Groups[1].Value
            $taskFailed += [int]$taskMatch.Groups[2].Value
            $taskIgnored += [int]$taskMatch.Groups[3].Value
        }
        foreach ($taskLine in $taskOutput) {
            $taskMatch = [regex]::Match($taskLine, 'MDO_EVIDENCE (\{.*\})')
            if ($taskMatch.Success) {
                try {
                    $taskParsed = $taskMatch.Groups[1].Value | ConvertFrom-Json -AsHashtable
                    foreach ($taskKey in @('case_id','group','questions','expected','passed','metrics','input_sha256','output_sha256')) {
                        if (-not $taskParsed.ContainsKey($taskKey)) { throw "Missing $taskKey" }
                    }
                    if ($taskParsed.passed -isnot [bool] -or $taskParsed.metrics -isnot [Collections.IDictionary]) {
                        throw 'Invalid evidence boolean/metrics object'
                    }
                    $taskCases.Add($taskParsed)
                } catch {
                    $taskSchemaErrors.Add("$($taskCommand.name): $($_.Exception.Message)")
                }
            }
        }
        $taskExecutions.Add([ordered]@{
            name = $taskCommand.name; command = 'cargo ' + ($taskArguments -join ' ')
            exit_code = $taskExitCode; passed = $taskPassed; failed = $taskFailed; ignored = $taskIgnored
            wall_seconds = [Math]::Round($taskWatch.Elapsed.TotalSeconds, 3); log = "$($taskCommand.name).log"
        })
        Write-Host "$($taskCommand.name): exit=$taskExitCode; passed=$taskPassed; failed=$taskFailed; ignored=$taskIgnored"
        if ($taskExitCode -ne 0) { $taskOutput | Select-Object -Last 18 | ForEach-Object { Write-Host $_ } }
    }
    $taskDuplicateIds = @($taskCases | Group-Object case_id | Where-Object Count -gt 1)
    $taskMissingCases = @($taskPlan.required_case_ids | Where-Object { $_ -cnotin @($taskCases | ForEach-Object { $_.case_id }) })
    foreach ($taskSource in $taskSources) {
        $taskCurrentHash = Get-TextHash ([IO.File]::ReadAllText((Join-Path $taskRoot $taskSource.path)).Replace("`r`n", "`n"))
        if ($taskCurrentHash -cne $taskSource.sha256_lf) { $taskSchemaErrors.Add("Source changed during the run: $($taskSource.path)") }
    }
    $taskSuccessful = @($taskExecutions | Where-Object { $_.exit_code -ne 0 -or $_.passed -eq 0 }).Count -eq 0 -and
        $taskCases.Count -gt 0 -and @($taskCases | Where-Object { $_.passed -ne $true }).Count -eq 0 -and
        $taskDuplicateIds.Count -eq 0 -and $taskSchemaErrors.Count -eq 0 -and $taskMissingCases.Count -eq 0
    $taskReport = [ordered]@{
        schema_version = 1; series = 'dissertation-contract-regression'; run_name = $RunName
        started_at_utc = $taskStarted.ToString('o'); finished_at_utc = [DateTime]::UtcNow.ToString('o')
        source = [ordered]@{ git_head = $taskRevision; working_tree_dirty_before_run = $taskDirty; sha256_lf = $taskSourceFingerprint; files = $taskSources }
        manuscript = [ordered]@{ name = 'manuscript_Denusiyk_D____20_09_2026.docx'; sha256 = 'e6dee7339fa2b0c19884b1e44be4a2e41c496f0d514e3da1bdd18b92d1449cc'; references = @('3.1', '3.3', '4.3/Table 4.5', '4.6/Table 4.11') }
        environment = $taskEnvironment
        sample_kind = 'generated control scenarios; not the original 492-object or 523-scenario corpus'
        decoder_independence = 'ND; separate decoding procedures can share critical libraries'
        timing_scope = 'test command wall time including compilation; not dissertation Q6 measurements'
        success = $taskSuccessful; cases_passed = @($taskCases | Where-Object { $_.passed -eq $true }).Count
        cases_total = $taskCases.Count; duplicate_case_ids = @($taskDuplicateIds | ForEach-Object Name)
        missing_required_case_ids = $taskMissingCases
        schema_errors = @($taskSchemaErrors); commands = @($taskExecutions); cases = @($taskCases)
    }
    Write-RunText 'results.json' ($taskReport | ConvertTo-Json -Depth 30)
    $taskCases | ForEach-Object {
        [pscustomobject]@{ case_id = $_.case_id; group = $_.group; questions = $_.questions -join ','; passed = $_.passed; expected = $_.expected; input_sha256 = $_.input_sha256; output_sha256 = $_.output_sha256; metrics_json = ConvertTo-Json $_.metrics -Depth 20 -Compress }
    } | Export-Csv -LiteralPath (Join-Path $taskRunDirectory 'cases.csv') -NoTypeInformation -Encoding utf8NoBOM
    $taskLines = [Collections.Generic.List[string]]::new()
    $taskLines.Add('# Результати контрольної серії')
    $taskLines.Add('')
    $taskLines.Add("Дата UTC: $($taskStarted.ToString('u')). Успішних сценаріїв: **$($taskReport.cases_passed)/$($taskReport.cases_total)**. Загальний результат: **$taskSuccessful**.")
    $taskLines.Add('')
    $taskLines.Add('Згенеровані контрольні сценарії за вимогами дисертації; це окрема серія, яка не замінює її оригінальні корпуси. Повні параметри, версії, контрольні суми та метрики — у [results.json](results.json); таблиця сценаріїв — у [cases.csv](cases.csv).')
    $taskLines.Add('')
    $taskLines.Add('| Перевірка | Успішні тести | Невдалі | Пропущені | Код завершення | Журнал |')
    $taskLines.Add('|---|---:|---:|---:|---:|---|')
    foreach ($taskExecution in $taskExecutions) { $taskLines.Add("| $($taskExecution.name) | $($taskExecution.passed) | $($taskExecution.failed) | $($taskExecution.ignored) | $($taskExecution.exit_code) | [log]($($taskExecution.log)) |") }
    $taskLines.Add('')
    $taskLines.Add('У workspace тести з FFmpeg пропущено навмисно й виконано окремими командами нижче; генератор тестових файлів не запускається. Час команд включає складання та не є оцінкою Q6. Незалежність реалізацій декодерів має статус ND.')
    $taskLines.Add('')
    $taskLines.Add('| Сценарій | Група | Питання | Критерій виконано |')
    $taskLines.Add('|---|---|---|---|')
    foreach ($taskCase in $taskCases) { $taskLines.Add("| $($taskCase.case_id) | $($taskCase.group) | $($taskCase.questions -join ', ') | $($taskCase.passed) |") }
    Write-RunText 'README.md' ($taskLines -join "`n")
    $taskHashes = @(Get-ChildItem -LiteralPath $taskRunDirectory -File | Sort-Object Name | ForEach-Object { "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($_.Name)" })
    Write-RunText 'SHA256SUMS' ($taskHashes -join "`n")
    Write-Host "Evidence saved: $taskRunDirectory"
    if (-not $taskSuccessful) { throw 'The series failed. Failed observations and command logs have been preserved.' }
} finally {
    Pop-Location
}
