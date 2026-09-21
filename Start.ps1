param([switch]$SmokeTest, [string]$SmokeImagePath)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

# Quote one argument according to the Windows C-runtime command-line rules.
# No shell evaluates paths, MIME values, or any other user input.
function ConvertTo-ProcessArgument([string]$Value) {
    if ($Value.IndexOf([char]0) -ge 0) { throw 'Аргумент містить недопустимий символ.' }
    $quoted = New-Object System.Text.StringBuilder
    [void]$quoted.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$quoted.Append(('\' * (2 * $slashes + 1)))
            [void]$quoted.Append('"')
        } else {
            [void]$quoted.Append(('\' * $slashes))
            [void]$quoted.Append($character)
        }
        $slashes = 0
    }
    [void]$quoted.Append(('\' * (2 * $slashes)))
    [void]$quoted.Append('"')
    return $quoted.ToString()
}

function New-TextLabel([string]$Text) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Dock = 'Fill'
    $label.TextAlign = 'MiddleLeft'
    return $label
}

function New-PathRow($TextBox, $Button) {
    $row = New-Object System.Windows.Forms.TableLayoutPanel
    $row.Dock = 'Fill'
    $row.Margin = New-Object System.Windows.Forms.Padding(0)
    $row.ColumnCount = 2
    [void]$row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    [void]$row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Absolute', 112)))
    $TextBox.Dock = 'Fill'
    $TextBox.Margin = New-Object System.Windows.Forms.Padding(0, 5, 10, 0)
    $Button.Dock = 'Fill'
    $Button.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 3)
    $row.Controls.Add($TextBox, 0, 0)
    $row.Controls.Add($Button, 1, 0)
    return $row
}

$script:applicationRoot = $PSScriptRoot
$script:executablePath = Join-Path $PSScriptRoot 'bin\mdocdr.exe'
$script:processState = $null
$script:resultDirectory = Join-Path $PSScriptRoot 'results'

$form = New-Object System.Windows.Forms.Form
$form.Text = 'MDO-CDR'
$form.Size = New-Object System.Drawing.Size(880, 740)
$form.MinimumSize = New-Object System.Drawing.Size(760, 670)
$form.StartPosition = 'CenterScreen'
$form.BackColor = [System.Drawing.Color]::FromArgb(247, 249, 252)
$form.ForeColor = [System.Drawing.Color]::FromArgb(28, 39, 54)
$form.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$form.AutoScaleMode = 'Dpi'

$layout = New-Object System.Windows.Forms.TableLayoutPanel
$layout.Dock = 'Fill'
$layout.Padding = New-Object System.Windows.Forms.Padding(24, 18, 24, 18)
$layout.ColumnCount = 1
$layout.RowCount = 12
foreach ($height in @(50, 34, 25, 38, 25, 38, 28, 38, 50, 30)) {
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Absolute', $height)))
}
[void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
[void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Absolute', 40)))
$form.Controls.Add($layout)

$heading = New-TextLabel 'MDO-CDR'
$heading.Font = New-Object System.Drawing.Font('Segoe UI', 25, [System.Drawing.FontStyle]::Bold)
$layout.Controls.Add($heading, 0, 0)
$subtitle = New-TextLabel 'Контрольована перебудова мультимедійних файлів'
$subtitle.ForeColor = [System.Drawing.Color]::FromArgb(83, 98, 119)
$layout.Controls.Add($subtitle, 0, 1)
$layout.Controls.Add((New-TextLabel 'Вхідний файл'), 0, 2)

$inputBox = New-Object System.Windows.Forms.TextBox
$inputBox.Name = 'InputPath'
$browseInput = New-Object System.Windows.Forms.Button
$browseInput.Text = 'Вибрати файл'
$layout.Controls.Add((New-PathRow $inputBox $browseInput), 0, 3)
$layout.Controls.Add((New-TextLabel 'Папка результатів'), 0, 4)
$outputBox = New-Object System.Windows.Forms.TextBox
$outputBox.Name = 'OutputDirectory'
$outputBox.Text = $script:resultDirectory
$browseOutput = New-Object System.Windows.Forms.Button
$browseOutput.Text = 'Вибрати папку'
$layout.Controls.Add((New-PathRow $outputBox $browseOutput), 0, 5)

$optionLabels = New-Object System.Windows.Forms.TableLayoutPanel
$optionLabels.Dock = 'Fill'
$optionLabels.Margin = New-Object System.Windows.Forms.Padding(0)
$optionLabels.ColumnCount = 2
[void]$optionLabels.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Absolute', 290)))
[void]$optionLabels.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
$optionLabels.Controls.Add((New-TextLabel 'Профіль оброблення'), 0, 0)
$optionLabels.Controls.Add((New-TextLabel 'Заявлений MIME-тип (необовʼязково)'), 1, 0)
$layout.Controls.Add($optionLabels, 0, 6)

$options = New-Object System.Windows.Forms.TableLayoutPanel
$options.Dock = 'Fill'
$options.Margin = New-Object System.Windows.Forms.Padding(0)
$options.ColumnCount = 2
[void]$options.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Absolute', 290)))
[void]$options.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
$profileBox = New-Object System.Windows.Forms.ComboBox
$profileBox.Name = 'Profile'
$profileBox.DropDownStyle = 'DropDownList'
$profileBox.Dock = 'Fill'
$profileBox.Margin = New-Object System.Windows.Forms.Padding(0, 3, 16, 0)
$profileBox.DisplayMember = 'Label'
$profiles = @(
    [pscustomobject]@{ Label = 'Дисертаційний (dissertation)'; Value = 'dissertation' },
    [pscustomobject]@{ Label = 'Стандартний (standard)'; Value = 'standard' },
    [pscustomobject]@{ Label = 'Суворий (strict)'; Value = 'strict' },
    [pscustomobject]@{ Label = 'Максимальний (paranoid)'; Value = 'paranoid' }
)
$profileBox.Items.AddRange([object[]]$profiles)
$profileBox.SelectedIndex = 0
$mimeBox = New-Object System.Windows.Forms.TextBox
$mimeBox.Name = 'DeclaredMime'
$mimeBox.Dock = 'Fill'
$mimeBox.Margin = New-Object System.Windows.Forms.Padding(0, 3, 0, 0)
$options.Controls.Add($profileBox, 0, 0)
$options.Controls.Add($mimeBox, 1, 0)
$layout.Controls.Add($options, 0, 7)

$actions = New-Object System.Windows.Forms.FlowLayoutPanel
$actions.Dock = 'Fill'
$actions.Margin = New-Object System.Windows.Forms.Padding(0, 7, 0, 0)
$runButton = New-Object System.Windows.Forms.Button
$runButton.Name = 'ProcessFile'
$runButton.Text = 'Обробити'
$runButton.Size = New-Object System.Drawing.Size(150, 34)
$runButton.BackColor = [System.Drawing.Color]::FromArgb(29, 91, 166)
$runButton.ForeColor = [System.Drawing.Color]::White
$runButton.FlatStyle = 'Flat'
$runButton.FlatAppearance.BorderSize = 0
$runButton.Margin = New-Object System.Windows.Forms.Padding(0)
$actions.Controls.Add($runButton)
$layout.Controls.Add($actions, 0, 8)
$statusLabel = New-TextLabel 'Оберіть файл і натисніть «Обробити».'
$statusLabel.Name = 'Status'
$layout.Controls.Add($statusLabel, 0, 9)

$resultBox = New-Object System.Windows.Forms.TextBox
$resultBox.Name = 'Result'
$resultBox.Dock = 'Fill'
$resultBox.Multiline = $true
$resultBox.ReadOnly = $true
$resultBox.ScrollBars = 'Vertical'
$resultBox.BackColor = [System.Drawing.Color]::White
$resultBox.BorderStyle = 'FixedSingle'
$resultBox.Text = 'Тут зʼявляться рішення, пояснення перевірки та шляхи до результатів.'
$layout.Controls.Add($resultBox, 0, 10)

$openButton = New-Object System.Windows.Forms.Button
$openButton.Name = 'OpenResults'
$openButton.Text = 'Відкрити папку результатів'
$openButton.Width = 245
$openButton.Dock = 'Left'
$openButton.Margin = New-Object System.Windows.Forms.Padding(0, 7, 0, 0)
$layout.Controls.Add($openButton, 0, 11)
$form.AcceptButton = $runButton

$browseInput.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = 'Виберіть мультимедійний файл'
    $dialog.Filter = 'Мультимедійні файли|*.png;*.jpg;*.jpeg;*.webp;*.bmp;*.tif;*.tiff;*.gif;*.apng;*.mp3;*.wav;*.flac;*.ogg;*.opus;*.mp4;*.m4a;*.webm;*.mkv|Усі файли|*.*'
    if ($dialog.ShowDialog($form) -eq 'OK') { $inputBox.Text = $dialog.FileName }
    $dialog.Dispose()
})
$browseOutput.Add_Click({
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Виберіть папку для обробленого файла та звіту'
    if ([System.IO.Directory]::Exists($outputBox.Text)) { $dialog.SelectedPath = $outputBox.Text }
    if ($dialog.ShowDialog($form) -eq 'OK') { $outputBox.Text = $dialog.SelectedPath }
    $dialog.Dispose()
})
$openButton.Add_Click({
    try {
        $directory = $script:resultDirectory
        if (-not [System.IO.Directory]::Exists($directory)) {
            $statusLabel.Text = 'Папка результатів ще не створена. Спочатку обробіть файл.'
            return
        }
        $openInfo = New-Object System.Diagnostics.ProcessStartInfo
        $openInfo.FileName = $directory
        $openInfo.UseShellExecute = $true
        [void][System.Diagnostics.Process]::Start($openInfo)
    } catch { $statusLabel.Text = 'Не вдалося відкрити папку: ' + $_.Exception.Message }
})

function Set-RunControls([bool]$Enabled) {
    foreach ($control in @($inputBox, $outputBox, $browseInput, $browseOutput, $profileBox, $mimeBox, $runButton)) {
        $control.Enabled = $Enabled
    }
}

function Format-DisplayPath([string]$Value) {
    if ($Value.StartsWith('\\?\UNC\')) { return '\\' + $Value.Substring(8) }
    if ($Value.StartsWith('\\?\')) { return $Value.Substring(4) }
    return $Value
}

function Show-ProcessResult([string]$Output, [string]$ErrorOutput, [int]$ExitCode) {
    $lines = New-Object 'System.Collections.Generic.List[string]'
    try {
        $report = $Output | ConvertFrom-Json
        if ($null -eq $report -or $null -eq $report.PSObject.Properties['released']) {
            throw 'Відповідь не містить результату перевірки.'
        }
        if ($ExitCode -eq 0 -and $report.released -eq $true) {
            $statusLabel.Text = 'Оброблення завершено. Результат створено.'
        } elseif ($ExitCode -eq 2) {
            $statusLabel.Text = 'Файл не надано. Перегляньте пояснення перевірки.'
        } else { $statusLabel.Text = 'Не вдалося завершити оброблення.' }
        $lines.Add($statusLabel.Text)
        if ($report.status) {
            $statusText = switch ([string]$report.status) {
                'Clean' { 'надання дозволено' }
                'Suspicious' { 'підозрілий файл' }
                'Blocked' { 'заблоковано' }
                'error' { 'помилка' }
                default { [string]$report.status }
            }
            $lines.Add('Рішення: ' + $statusText)
        }
        if ($report.output_path -and $report.released -eq $true) {
            $lines.Add('Файл: ' + (Format-DisplayPath ([string]$report.output_path)))
        }
        if ($report.report_path) { $lines.Add('Звіт: ' + (Format-DisplayPath ([string]$report.report_path))) }
        if ($report.error) {
            $errorText = [string]$report.error
            if ($errorText -eq 'File type mismatch between extension, declared MIME, and content') {
                $errorText = 'Розширення файла, заявлений MIME-тип і вміст не узгоджені.'
            }
            $lines.Add('Причина: ' + $errorText)
        }
        if ($report.alerts) {
            $lines.Add('')
            $lines.Add('Повідомлення перевірки:')
            foreach ($alert in $report.alerts) {
                if ($alert -is [string]) { $lines.Add('• ' + $alert) }
                elseif ($alert.message) { $lines.Add('• ' + [string]$alert.message) }
                else { $lines.Add('• ' + ($alert | ConvertTo-Json -Compress -Depth 4)) }
            }
        }
    } catch {
        $statusLabel.Text = 'Не вдалося прочитати результат оброблення.'
        $lines.Add($statusLabel.Text)
        $lines.Add($_.Exception.Message)
        if ($Output.Trim()) { $lines.Add($Output.Trim()) }
    }
    if ($ErrorOutput.Trim()) {
        $lines.Add('')
        $lines.Add('Додаткові відомості:')
        $lines.Add($ErrorOutput.Trim())
    }
    $resultBox.Text = $lines -join [Environment]::NewLine
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 200
$timer.Add_Tick({
    if ($null -eq $script:processState) { return }
    $state = $script:processState
    if (-not $state.Process.HasExited -or -not $state.Output.IsCompleted -or -not $state.Error.IsCompleted) { return }
    $timer.Stop()
    try {
        Show-ProcessResult -Output ($state.Output.GetAwaiter().GetResult()) -ErrorOutput ($state.Error.GetAwaiter().GetResult()) -ExitCode $state.Process.ExitCode
    } catch {
        $statusLabel.Text = 'Не вдалося отримати результат.'
        $resultBox.Text = $_.Exception.Message
    } finally {
        $state.Process.Dispose()
        $script:processState = $null
        Set-RunControls $true
    }
})

$runButton.Add_Click({
    $process = $null
    try {
        if (-not [System.IO.File]::Exists($script:executablePath)) {
            throw 'Не знайдено bin\mdocdr.exe. Відновіть повний комплект програми.'
        }
        if (-not [System.IO.File]::Exists($inputBox.Text)) { throw 'Виберіть наявний вхідний файл.' }
        if ([string]::IsNullOrWhiteSpace($outputBox.Text)) { throw 'Виберіть папку результатів.' }
        $inputPath = [System.IO.Path]::GetFullPath($inputBox.Text)
        $outputDirectory = [System.IO.Path]::GetFullPath($outputBox.Text)
        $argumentValues = @('--input', $inputPath, '--output-dir', $outputDirectory, '--profile', [string]$profileBox.SelectedItem.Value, '--json')
        if (-not [string]::IsNullOrWhiteSpace($mimeBox.Text)) { $argumentValues += @('--mime', $mimeBox.Text.Trim()) }
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $script:executablePath
        $startInfo.WorkingDirectory = $script:applicationRoot
        $startInfo.Arguments = ($argumentValues | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' '
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.WindowStyle = 'Hidden'
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
        $startInfo.StandardErrorEncoding = New-Object System.Text.UTF8Encoding($false)
        $runtimePath = Join-Path $script:applicationRoot 'runtime-paths.json'
        if ([System.IO.File]::Exists($runtimePath)) {
            $runtime = Get-Content -LiteralPath $runtimePath -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($component in @('ffmpeg', 'ffprobe')) {
                $property = $runtime.PSObject.Properties[$component]
                if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                    $componentPath = [string]$property.Value
                    if (-not [System.IO.Path]::IsPathRooted($componentPath)) {
                        $componentPath = Join-Path $script:applicationRoot $componentPath
                    }
                    if (-not [System.IO.File]::Exists($componentPath)) { throw ('Не знайдено ' + $component + ': ' + $componentPath) }
                    $startInfo.EnvironmentVariables['MDO_CDR_' + $component.ToUpperInvariant()] = $componentPath
                }
            }
        }
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        [void]$process.Start()
        $script:processState = [pscustomobject]@{
            Process = $process
            Output = $process.StandardOutput.ReadToEndAsync()
            Error = $process.StandardError.ReadToEndAsync()
        }
        $script:resultDirectory = $outputDirectory
        Set-RunControls $false
        $statusLabel.Text = 'Триває оброблення…'
        $resultBox.Text = 'Вхідний файл: ' + $inputPath + [Environment]::NewLine + 'Профіль: ' + $profileBox.SelectedItem.Label
        $timer.Start()
    } catch {
        if ($null -ne $process -and $null -eq $script:processState) { $process.Dispose() }
        $statusLabel.Text = 'Перевірте параметри запуску.'
        $resultBox.Text = $_.Exception.Message
    }
})

$form.Add_FormClosing({
    if ($null -ne $script:processState) {
        $_.Cancel = $true
        $statusLabel.Text = 'Триває оброблення. Вікно можна закрити після завершення.'
    }
})

try {
    if ($SmokeTest) {
        $form.CreateControl()
        $form.PerformLayout()
        if ($SmokeImagePath) {
            # Instantiate child handles without displaying a window to the user.
            $form.ShowInTaskbar = $false
            $form.Opacity = 0
            $form.Show()
            [System.Windows.Forms.Application]::DoEvents()
            $bitmap = New-Object System.Drawing.Bitmap($form.Width, $form.Height)
            try {
                $form.DrawToBitmap($bitmap, (New-Object System.Drawing.Rectangle(0, 0, $form.Width, $form.Height)))
                $bitmap.Save([System.IO.Path]::GetFullPath($SmokeImagePath), [System.Drawing.Imaging.ImageFormat]::Png)
            } finally { $bitmap.Dispose(); $form.Hide() }
        }
        $quoteChecks = @(
            (ConvertTo-ProcessArgument '') -eq '""'
            (ConvertTo-ProcessArgument 'C:\файли з пробілом\a.png') -eq '"C:\файли з пробілом\a.png"'
            (ConvertTo-ProcessArgument 'C:\end\') -eq '"C:\end\\"'
            (ConvertTo-ProcessArgument 'a"b') -eq '"a\"b"'
            (ConvertTo-ProcessArgument 'a&b;$(x)') -eq '"a&b;$(x)"'
        )
        if ($quoteChecks -contains $false) { throw 'Помилка перевірки передавання аргументів.' }
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
        [pscustomobject]@{
            ok = $true
            title = $form.Text
            default_profile = $profileBox.SelectedItem.Value
            profiles = @($profiles | ForEach-Object { $_.Value })
            controls = @($inputBox.Name, $outputBox.Name, $profileBox.Name, $mimeBox.Name, $runButton.Name, $resultBox.Name, $openButton.Name)
            output_directory = $outputBox.Text
            executable = $script:executablePath
            executable_exists = [System.IO.File]::Exists($script:executablePath)
            argument_quote_checks = $quoteChecks.Count
            shown = $false
        } | ConvertTo-Json -Compress
    } else { [void]$form.ShowDialog() }
} finally {
    $timer.Dispose()
    $form.Dispose()
}
