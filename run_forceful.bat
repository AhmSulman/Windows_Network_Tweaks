@echo off
setlocal EnableDelayedExpansion

REM Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process '%~0' -Verb RunAs"
    exit /b
)

echo ========================================================
echo      ENCRYPT ADAPTERS - FORCEFUL NETWORK RESET
echo ========================================================

echo.
echo [1/6] Resetting Winsock Catalog...
netsh winsock reset
if %errorLevel% neq 0 echo Failed to reset Winsock.

echo.
echo [2/6] Resetting TCP/IP Stack...
netsh int ip reset
if %errorLevel% neq 0 echo Failed to reset TCP/IP.

echo.
echo [3/6] Resetting Windows Firewall to Default...
netsh advfirewall reset
if %errorLevel% neq 0 echo Failed to reset Firewall.

echo.
echo [4/6] Flushing DNS Cache...
ipconfig /flushdns

echo.
echo [5/6] Clearing Network Profiles (Registry)...
REM Deletes saved network profiles (WiFi definitions, identified networks)
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /f >nul 2>&1
if %errorLevel% equ 0 (
    echo    - Network profiles cleared.
) else (
    echo    - Failed to clear network profiles (or key empty).
)

REM Clear Managed Network Signatures if present
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed" /f >nul 2>&1

echo.
echo [6/6] Releasing and Renewing IP...
ipconfig /release >nul 2>&1
ipconfig /renew >nul 2>&1

echo.
echo ========================================================
echo      NETWORK RESET COMPLETE
echo ========================================================
echo.

REM Now run the main C# application
echo Starting EncryptAdapters...
cd /d "%~dp0"
dotnet run -- %*

pause
