@echo off
cl /nologo /TC /W4 /WX /O2 /Zi /MT /GS /sdl /guard:cf /DUNICODE /D_UNICODE iptray.c /link /subsystem:windows /incremental:no /dynamicbase /nxcompat user32.lib gdi32.lib shell32.lib iphlpapi.lib ws2_32.lib
if errorlevel 1 exit /b 1
start "" /wait iptray.exe --self-test
if errorlevel 1 (
  echo iptray self-test: FAIL
  exit /b 1
)
echo iptray self-test: PASS
