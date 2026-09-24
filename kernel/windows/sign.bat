@echo off
rem SPDX-License-Identifier: MIT
rem
rem Windows-side signing of build\{x64,arm64}\nanochrono.sys.
rem
rem Kept for compatibility: the work is done by autosign.bat, which reuses
rem certs-private\nanochrono-test.pfx (from sign.sh / certs\make-test-cert.sh
rem on Linux) or creates a self-signed test certificate with PowerShell, then
rem signs with osslsigncode (signtool if osslsigncode is absent).
rem
rem   sign.bat [/trust] [/testsigning]     see autosign.bat
rem
rem Output: build\signed\{x64,arm64}\nanochrono.sys

call "%~dp0autosign.bat" %*
exit /b %errorlevel%
