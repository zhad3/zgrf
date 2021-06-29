@IF NOT DEFINED VSINSTALLDIR (
    echo Visual Studio wasn't found. Make sure you run the command from Visual Studio or using the Visual Studio Developer Console.
    exit /b 1
)
@IF EXIST "%~dp0c\build\LzmaDec.obj" (
    exit /b 0
)

cl.exe /Fo"%~dp0c\\build\\" /c "%~dp0c\\lzma\\LzmaDec.c"

@IF errorlevel 1 (
    echo Compilation error occurred.
    exit /b 1
)
