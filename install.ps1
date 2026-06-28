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

    # checksum (best-effort)
    try {
        $sumFile = "$zip.sha256"
        Invoke-WebRequest -Uri "$url.sha256" -OutFile $sumFile -UseBasicParsing
        $want = (Get-Content $sumFile -Raw).Split()[0].Trim().ToLower()
        $got  = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
        if ($want -and ($want -ne $got)) { throw "контрольная сумма не сошлась (ожидал $want, получил $got)" }
        Write-Host "checksum ok"
    } catch { Write-Host "checksum пропущен" }

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
