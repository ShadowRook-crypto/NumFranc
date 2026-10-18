@echo off
rem NumFranc - lanceur Windows (double-clic)
chcp 65001 >nul
cd /d "%~dp0"
set "BIN=bin\numfranc-windows-x86_64.exe"
if exist "%BIN%" goto run

set "BIN=code\target\release\numfranc.exe"
if exist "%BIN%" goto run
if exist "%USERPROFILE%\.cargo\bin\cargo.exe" set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
where cargo >nul 2>nul
if errorlevel 1 (
  echo Installation de Rust - une seule fois...
  curl -sSfL -o "%TEMP%\rustup-init.exe" https://win.rustup.rs/x86_64 || goto fail
  "%TEMP%\rustup-init.exe" -y --default-host x86_64-pc-windows-gnu || goto fail
  set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
)
echo Compilation de NumFranc - 1 a 3 minutes la premiere fois...
cargo build --release --manifest-path code\Cargo.toml || goto fail

:run
"%BIN%" %*
pause
exit /b 0

:fail
echo Echec de l'installation.
pause
exit /b 1
