@echo off
set OLD_CD=%CD%

set PACKAGE_DIR=%~1
set ARCH=%DUB_ARCH%
set BUILD_TYPE=%DUB_BUILD_TYPE%

set DEST_DIR=%PACKAGE_DIR%\c\build\%ARCH%-%BUILD_TYPE%

IF NOT EXIST "%DEST_DIR%" (
    mkdir "%DEST_DIR%"
)

IF EXIST "%DEST_DIR%\LzmaDec.obj" IF "%DUB_FORCE%"=="" (
    exit /b 0
)

IF NOT DEFINED VSINSTALLDIR (
    echo Visual Studio wasn't found. Make sure you run the command from Visual Studio or using the Visual Studio Developer Console.
    exit /b 1
)

set "DEST_DIR2=%DEST_DIR:\=\\%"
set "PACKAGE_DIR2=%PACKAGE_DIR:\=\\%"

cl.exe /Fo"%DEST_DIR2%\\LzmaDec.obj" /c "%PACKAGE_DIR2%\\c\\lzma\\LzmaDec.c"

@IF errorlevel 1 (
    echo Compilation error occurred.
    exit /b 1
)
