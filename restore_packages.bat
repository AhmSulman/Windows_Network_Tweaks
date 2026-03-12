@echo off
REM Restore NuGet packages for EncryptAdapters (dotnet restore)
setlocal
cd /d "%~dp0"

echo Restoring NuGet packages...
dotnet restore
if errorlevel 1 (
    echo.
    echo Restore failed. Make sure the .NET SDK is installed: https://dotnet.microsoft.com/download
    exit /b 1
)
echo.
echo Restore completed successfully.
exit /b 0
