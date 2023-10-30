@echo off
@setlocal enableextensions
@cd /d "%~dp0\..\"

for /f "usebackq tokens=*" %%a in (`call "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -prerelease -products * -requires Microsoft.Component.MSBuild -property installationPath`) do (
   set "VSINSTALLPATH=%%a"
)

if not defined VSINSTALLPATH (
   echo No Visual Studio installation detected.
   goto end
)

if exist "%VSINSTALLPATH%\VC\Auxiliary\Build\vcvarsall.bat" (
   call "%VSINSTALLPATH%\VC\Auxiliary\Build\vcvarsall.bat" amd64_arm64
) else (
   goto end
)

msbuild /m SystemInformer.sln -property:Configuration=Debug -property:Platform=Win32 -verbosity:normal
if %ERRORLEVEL% neq 0 goto end

msbuild /m SystemInformer.sln -property:Configuration=Debug -property:Platform=x64 -verbosity:normal
if %ERRORLEVEL% neq 0 goto end

msbuild /m SystemInformer.sln -property:Configuration=Debug -property:Platform=ARM64 -verbosity:normal
if %ERRORLEVEL% neq 0 goto end

msbuild /m Plugins\Plugins.sln -property:Configuration=Debug -property:Platform=Win32 -verbosity:normal
if %ERRORLEVEL% neq 0 goto end

msbuild /m Plugins\Plugins.sln -property:Configuration=Debug -property:Platform=x64 -verbosity:normal
if %ERRORLEVEL% neq 0 goto end

msbuild /m Plugins\Plugins.sln -property:Configuration=Debug -property:Platform=ARM64 -verbosity:normal
if %ERRORLEVEL% neq 0 goto end

:end
pause
