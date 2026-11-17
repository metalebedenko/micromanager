# micromanager installer (Windows, PowerShell).
#
#   irm https://raw.githubusercontent.com/metalebedenko/micromanager/main/install.ps1 | iex
#
# Скачивает готовый бинарь из последнего GitHub Release и кладёт в
# %LOCALAPPDATA%\micromanager\bin, добавляя его в пользовательский PATH.
$ErrorActionPreference = 'Stop'

$Repo = 'metalebedenko/micromanager'
$Bin  = 'micromanager'

# --- архитектура (готовый бинарь — x86_64) ---
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne 'AMD64') {
    throw "для Windows $arch нет готового бинаря — собери из исходников: cargo install --git https://github.com/$Repo"
}

$asset = "$Bin-windows-x86_64.zip"
$url   = "https://github.com/$Repo/releases/latest/download/$asset"

$installDir = Join-Path $env:LOCALAPPDATA 'micromanager\bin'
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("mm-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    Write-Host "downloading $asset ..."
    $zip = Join-Path $tmp $asset
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

    $sumFile = "$zip.sha256"
    Invoke-WebRequest -Uri "$url.sha256" -OutFile $sumFile -UseBasicParsing
    $sumText = (Get-Content -LiteralPath $sumFile -Raw).Trim()
    $pattern = '\A(?<hash>[0-9a-fA-F]{64})[ \t]+\*?' + [regex]::Escape($asset) + '\z'
    $entry = [regex]::Match($sumText, $pattern)
    if (-not $entry.Success) { throw "некорректный файл SHA-256 для $asset" }
    $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash
    if ($got -ine $entry.Groups['hash'].Value) { throw "контрольная сумма архива не совпадает" }
    Write-Host "SHA-256 verified"

    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    $exe = Join-Path $tmp "$Bin.exe"
    if (-not (Test-Path $exe)) { throw "в архиве нет $Bin.exe" }

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Copy-Item -Path $exe -Destination (Join-Path $installDir "$Bin.exe") -Force
    Write-Host "installed: $installDir\$Bin.exe"

    # --- добавить в пользовательский PATH ---
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$installDir*") {
        [Environment]::SetEnvironmentVariable('Path', "$installDir;$userPath", 'User')
        Write-Host "PATH обновлён — перезапусти терминал."
    }

    Write-Host ""
    Write-Host "Готово. Запусти:  $Bin tui   (или: $Bin listen)"
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
