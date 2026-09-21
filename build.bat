@echo off
REM ---------------------------------------------------------------
REM  Builds dist\NetScope.exe  -  run this once, from this folder.
REM  Needs Python 3.9+ on PATH. Does not need admin.
REM ---------------------------------------------------------------
setlocal

where python >nul 2>&1
if errorlevel 1 (
  echo.
  echo   Python was not found on PATH.
  echo   Install it from https://www.python.org/downloads/windows/
  echo   and tick "Add python.exe to PATH" in the installer.
  echo.
  exit /b 1
)

echo.
echo === Installing build dependencies ===
python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller
if errorlevel 1 (
  echo.
  echo   Dependency install failed. See the messages above.
  exit /b 1
)

echo.
echo === Building NetScope.exe ===
python -m PyInstaller --noconfirm --clean ^
  --onefile ^
  --console ^
  --name NetScope ^
  --icon netscope.ico ^
  --collect-all scapy ^
  --hidden-import netscope_ui ^
  --hidden-import netscope_smb ^
  --hidden-import netscope_streams ^
  --hidden-import netscope_pcap ^
  --hidden-import netscope_quic ^
  --hidden-import netscope_alerts ^
  --hidden-import netscope_history ^
  --hidden-import netscope_tray ^
  --hidden-import netscope_l2 ^
  --hidden-import netscope_conn ^
  --collect-submodules cryptography ^
  --collect-submodules pystray ^
  --uac-admin ^
  netscope.py
if errorlevel 1 (
  echo.
  echo   Build failed. See the messages above.
  exit /b 1
)

echo.
echo === Building NetScopeTray.exe (no console window) ===
REM Same program, built for the windows subsystem so nothing flashes up and
REM nothing lingers when you launch it from a shell. It implies --tray.
python -m PyInstaller --noconfirm --clean ^
  --onefile ^
  --noconsole ^
  --name NetScopeTray ^
  --icon netscope.ico ^
  --collect-all scapy ^
  --hidden-import netscope_ui ^
  --hidden-import netscope_smb ^
  --hidden-import netscope_streams ^
  --hidden-import netscope_pcap ^
  --hidden-import netscope_quic ^
  --hidden-import netscope_alerts ^
  --hidden-import netscope_history ^
  --hidden-import netscope_tray ^
  --hidden-import netscope_l2 ^
  --hidden-import netscope_conn ^
  --collect-submodules cryptography ^
  --collect-submodules pystray ^
  --uac-admin ^
  netscope.py
if errorlevel 1 (
  echo.
  echo   Tray build failed. NetScope.exe above is still usable with --tray.
)

echo.
echo   Run the tests with:  python tests\run_tests.py
echo.
echo ===============================================================
echo   Done.  Your apps are at:
echo     %CD%\dist\NetScope.exe       console - CLI, --list, --read, etc.
echo     %CD%\dist\NetScopeTray.exe   no console - double-click for the tray
echo.
echo   It will ask for administrator rights when you launch it -
echo   packet capture needs them.
echo.
echo   If capture fails, install Npcap first: https://npcap.com
echo ===============================================================
echo.
endlocal
