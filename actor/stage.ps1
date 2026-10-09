# The stage run with one command, from the repository root:
#
#     powershell -ExecutionPolicy Bypass -File actor\stage.ps1          start everything, run once
#     python -m actor.stage                                             every further run
#     powershell -ExecutionPolicy Bypass -File actor\stage.ps1 -Stop    close the three windows
#
# It opens the controlled target, the scanner and the Actor in a window each, after stopping
# any earlier copies: two scanners at once get in each other's way.
param([switch]$Stop, [switch]$NoRun)

$root = Split-Path -Parent $PSScriptRoot
$modules = 'actor.mock_registrar_server', 'brain.worker', 'actor.intake'

function Stop-Stage {
    Get-CimInstance Win32_Process -Filter "Name = 'python.exe' OR Name = 'powershell.exe'" |
        Where-Object {
            $line = $_.CommandLine
            $line -and $line -notlike '*stage.ps1*' -and ($modules | Where-Object { $line -like "*-m $_*" })
        } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

Stop-Stage
if ($Stop) {
    Write-Host 'stage processes stopped'
    return
}

$env:PYTHONUTF8 = '1'
$env:BRAIN_ALLOW_PRIVATE = '1'
if (-not $env:SEMGREP_BIN -and (Test-Path 'C:\sg\Scripts\semgrep.exe')) {
    $env:SEMGREP_BIN = 'C:/sg/Scripts/semgrep.exe'
}

$windows = @(
    @('1 controlled target', 'python -m actor.mock_registrar_server'),
    @('2 scanner', 'python -m brain.worker --interval 3'),
    @('3 actor', 'python -u -m actor.intake --live --loop --interval 5')
)
foreach ($window in $windows) {
    $command = "`$host.UI.RawUI.WindowTitle = '$($window[0])'; $($window[1])"
    Start-Process powershell -WorkingDirectory $root -ArgumentList '-NoExit', '-Command', $command
}

if (-not $NoRun) {
    Start-Sleep -Seconds 10
    Set-Location $root
    python -m actor.stage
}
