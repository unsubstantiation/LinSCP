@rem Stub gradlew.bat for Windows CI
@echo off
if "%1"=="assembleDebug" (
  mkdir app\build\outputs\apk\debug 2>nul
  echo dummy apk> app\build\outputs\apk\debug\app-debug.apk
  exit /b 0
)
gradle %*
