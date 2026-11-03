@echo off
rem Builds IPQuality.exe with the C# compiler that ships with Windows (.NET Framework 4.x). No SDK needed.
setlocal
set NET=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319
"%NET%\csc.exe" /nologo /target:winexe /optimize+ /codepage:65001 ^
  /out:"%~dp0IPQuality.exe" ^
  /win32icon:"%~dp0src\app.ico" /win32manifest:"%~dp0src\app.manifest" ^
  /r:"%NET%\WPF\PresentationFramework.dll" /r:"%NET%\WPF\PresentationCore.dll" /r:"%NET%\WPF\WindowsBase.dll" ^
  /r:System.Xaml.dll /r:System.dll /r:System.Core.dll ^
  "%~dp0src\IpQuality.cs"
exit /b %errorlevel%
