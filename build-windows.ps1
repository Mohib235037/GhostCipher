param([string]$PythonExe = '', [string]$VenvPath = '.venv')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$CheckPython = "import platform,sys; assert sys.platform == 'win32' and platform.machine().lower() == 'amd64' and sys.version_info >= (3,12), 'Windows x64 and Python 3.12+ are required'"
if ($PythonExe) {
    & $PythonExe -c $CheckPython
    if ($LASTEXITCODE -ne 0) { throw 'Unsupported Python.' }
    & $PythonExe -m venv $VenvPath
} else {
    & py -3.12 -c $CheckPython
    if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.12+ x64 or pass -PythonExe.' }
    & py -3.12 -m venv $VenvPath
}
if ($LASTEXITCODE -ne 0) { throw 'venv creation failed.' }
$BuildPython = (Resolve-Path -LiteralPath (Join-Path $VenvPath 'Scripts\python.exe')).Path
& $BuildPython -m pip install --only-binary=:all: -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
& $BuildPython -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Installed packages do not satisfy the lock files.' }
New-Item -ItemType Directory -Path build -Force | Out-Null
& $BuildPython -m pytest -q --junitxml=build\tests.xml
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
& $BuildPython tools\prepare.py
if ($LASTEXITCODE -ne 0) { throw 'Document preparation failed.' }
& $BuildPython -m PyInstaller --noconfirm --workpath build\pyinstaller GhostCipher.spec
if ($LASTEXITCODE -ne 0) { throw 'EXE build failed.' }
$BuiltExe = Join-Path $PSScriptRoot 'dist\GhostCipher\GhostCipher.exe'
$SmokeReport = Join-Path $PSScriptRoot 'build\exe-smoke.json'
$SmokeProcess = Start-Process -FilePath $BuiltExe -ArgumentList '--smoke-test', ('"' + $SmokeReport + '"') -WindowStyle Hidden -PassThru
if (-not $SmokeProcess.WaitForExit(180000)) {
    Stop-Process -Id $SmokeProcess.Id -Force
    throw 'Packaged GUI smoke test timed out.'
}
if ($SmokeProcess.ExitCode -ne 0) { throw 'Packaged GUI smoke test failed.' }
& $BuildPython tools\package.py
if ($LASTEXITCODE -ne 0) { throw 'Packaging failed.' }
Write-Host "Ready: $BuiltExe"
