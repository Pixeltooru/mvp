@echo off
echo ========================================
echo Building Android APK
echo ========================================

echo.
echo Step 1: Cleaning build cache...
flutter clean

echo.
echo Step 2: Removing build directory...
rmdir /s /q build 2>nul

echo.
echo Step 3: Getting dependencies...
flutter pub get

echo.
echo Step 4: Building APK (Release)...
flutter build apk --release

echo.
echo ========================================
echo Build Complete!
echo ========================================
echo.
echo APK location:
echo build\app\outputs\flutter-apk\app-release.apk
echo.
pause
