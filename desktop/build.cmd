@echo off
rem Builds build\APK-Signer.exe (and the build\selftest.exe test harness) with MSVC x64.
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
rem "call" keeps cmd from mangling the quoted path, which has parentheses in it.
for /f "usebackq delims=" %%i in (`call "%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find VC\Auxiliary\Build\vcvars64.bat`) do set "VCVARS=%%i"
if not defined VCVARS (
    echo Visual Studio with the C++ x64 build tools was not found.
    exit /b 1
)
rem vcvars looks for vswhere on PATH and complains if it is not there.
set "PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer;%PATH%"
call "%VCVARS%" >nul || exit /b 1
cd /d "%~dp0"
if not exist build mkdir build

rem Only the raw deflate and inflate parts of miniz are used.
set MINIZ=/DMINIZ_NO_STDIO /DMINIZ_NO_TIME /DMINIZ_NO_ARCHIVE_APIS /DMINIZ_NO_ZLIB_COMPATIBLE_NAMES
set COMMON=/nologo /utf-8 /O1 /MT /DUNICODE /D_UNICODE %MINIZ% /Fobuild\
set LIBS=user32.lib gdi32.lib shell32.lib ole32.lib uuid.lib comctl32.lib crypt32.lib bcrypt.lib

rc /nologo /fo build\apk_signer.res apk_signer.rc || exit /b 1
cl %COMMON% /W3 /c third_party\miniz\miniz.c || exit /b 1
cl %COMMON% /std:c++20 /W4 /EHsc apk_signer.cpp build\miniz.obj build\apk_signer.res /link /SUBSYSTEM:WINDOWS /MANIFEST:NO /OUT:build\APK-Signer.exe %LIBS% || exit /b 1
cl %COMMON% /std:c++20 /W4 /EHsc tests\selftest.cpp build\miniz.obj build\apk_signer.res /link /SUBSYSTEM:CONSOLE /MANIFEST:NO /OUT:build\selftest.exe %LIBS% || exit /b 1
for %%f in (build\APK-Signer.exe) do echo Built %%~ff (%%~zf bytes)
