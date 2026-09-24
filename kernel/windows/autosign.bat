@echo off
rem SPDX-License-Identifier: MIT
rem
rem autosign.bat - self-signs the NanoChronometer driver on Windows, end to end.
rem
rem   autosign.bat                 create the test certificate if missing, then
rem                                sign build\{x64,arm64}\nanochrono.sys with
rem                                osslsigncode (signtool if osslsigncode is absent)
rem   autosign.bat /trust          also install the certificate in LocalMachine
rem                                Root + TrustedPublisher            (Administrator)
rem   autosign.bat /testsigning    also run `bcdedit /set testsigning on`
rem                                (Administrator; takes effect after a reboot)
rem
rem The certificate is SELF-SIGNED and TEST-ONLY. Windows loads a driver signed
rem with it only in test-signing mode; it is not, and cannot become, a
rem production signature (that needs an EV certificate and Microsoft's
rem attestation signing). Trusting it with /trust adds a root certificate whose
rem private key sits in certs-private\ on this machine: anyone holding that
rem key can sign code this machine then trusts. Keep certs-private\ private and
rem remove the certificate (certmgr.msc) when done.
rem
rem Output: build\signed\{x64,arm64}\nanochrono.sys
rem
rem osslsigncode for Windows: https://github.com/mtrojnar/osslsigncode/releases
rem (or `winget install osslsigncode`, `scoop install osslsigncode`).

setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "KEYS=certs-private"
set "PFX=%KEYS%\nanochrono-test.pfx"
set "CER=certs\nanochrono-test.crt"
set "OUT=build\signed"
rem The PFX needs a password for Export-PfxCertificate; it protects nothing a
rem file-system ACL does not, so a fixed one is used. Override with NC_PFX_PASS.
if not defined NC_PFX_PASS set "NC_PFX_PASS=nanochrono"

set "DO_TRUST=0"
set "DO_TESTSIGN=0"
:args
if "%~1"=="" goto :args_done
if /i "%~1"=="/trust" set "DO_TRUST=1"
if /i "%~1"=="/testsigning" set "DO_TESTSIGN=1"
shift
goto :args
:args_done

if not exist "%KEYS%" mkdir "%KEYS%"
if not exist "certs" mkdir "certs"
if not exist "%OUT%\x64" mkdir "%OUT%\x64"
if not exist "%OUT%\arm64" mkdir "%OUT%\arm64"

rem ---------------------------------------------------------------------------
rem 1. The certificate: reuse the one sign.sh / make-test-cert.sh made, or
rem    create one with PowerShell (a code-signing cert in CurrentUser\My).
rem ---------------------------------------------------------------------------
if exist "%PFX%" (
    echo == reusing %PFX%
) else (
    echo == creating a self-signed TEST code-signing certificate
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "$ErrorActionPreference='Stop';" ^
      "$c = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=NanoChronometer Test (DO NOT TRUST), O=NanoChronometer Test' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(5) -CertStoreLocation Cert:\CurrentUser\My;" ^
      "$p = ConvertTo-SecureString -String $env:NC_PFX_PASS -Force -AsPlainText;" ^
      "Export-PfxCertificate -Cert $c -FilePath '%PFX%' -Password $p | Out-Null;" ^
      "Export-Certificate -Cert $c -FilePath '%CER%' -Type CERT | Out-Null;" ^
      "Remove-Item -Path ('Cert:\CurrentUser\My\' + $c.Thumbprint);" ^
      "Write-Host ('== thumbprint ' + $c.Thumbprint)"
    if errorlevel 1 (
        echo ERROR: certificate creation failed.
        exit /b 1
    )
    echo == created %PFX% and %CER%
)

rem A PFX made by make-test-cert.sh on Linux has an empty password.
set "PASS=%NC_PFX_PASS%"
if exist "%KEYS%\nanochrono-test.key" set "PASS="

rem ---------------------------------------------------------------------------
rem 2. Sign both architectures.
rem ---------------------------------------------------------------------------
set "SIGNED=0"
where osslsigncode >nul 2>nul
if !errorlevel!==0 (
    for %%a in (x64 arm64) do (
        if exist "build\%%a\nanochrono.sys" (
            echo == osslsigncode: build\%%a\nanochrono.sys
            if exist "%OUT%\%%a\nanochrono.sys" del /q "%OUT%\%%a\nanochrono.sys"
            osslsigncode sign -pkcs12 "%PFX%" -pass "!PASS!" -h sha256 ^
                -n "NanoChronometer test driver" ^
                -in "build\%%a\nanochrono.sys" -out "%OUT%\%%a\nanochrono.sys"
            if errorlevel 1 exit /b 1
            osslsigncode verify -CAfile "%CER%" -in "%OUT%\%%a\nanochrono.sys" >nul 2>nul
            set /a SIGNED+=1
        ) else (
            echo -- skipping %%a: build\%%a\nanochrono.sys not found
        )
    )
    goto :signed
)

where signtool >nul 2>nul
if !errorlevel!==0 (
    for %%a in (x64 arm64) do (
        if exist "build\%%a\nanochrono.sys" (
            echo == signtool: build\%%a\nanochrono.sys
            copy /y "build\%%a\nanochrono.sys" "%OUT%\%%a\nanochrono.sys" >nul
            signtool sign /f "%PFX%" /p "!PASS!" /fd SHA256 "%OUT%\%%a\nanochrono.sys"
            if errorlevel 1 exit /b 1
            set /a SIGNED+=1
        ) else (
            echo -- skipping %%a: build\%%a\nanochrono.sys not found
        )
    )
    goto :signed
)

echo ERROR: neither osslsigncode nor signtool found.
echo        winget install osslsigncode   (or the WDK for signtool)
exit /b 1

:signed
if !SIGNED!==0 (
    echo ERROR: nothing signed - build the driver first ^(make all^).
    exit /b 1
)

rem ---------------------------------------------------------------------------
rem 3. Optional, Administrator: trust the certificate, enable test signing.
rem ---------------------------------------------------------------------------
if !DO_TRUST!==1 (
    echo == trusting %CER% ^(LocalMachine Root + TrustedPublisher^)
    echo    WARNING: a root certificate whose key is in %KEYS%\ - remove it when done.
    certutil -addstore -f Root "%CER%" || exit /b 1
    certutil -addstore -f TrustedPublisher "%CER%" || exit /b 1
)
if !DO_TESTSIGN!==1 (
    echo == enabling test signing ^(reboot required; Secure Boot must be off^)
    bcdedit /set testsigning on || exit /b 1
)

echo.
echo == done: !SIGNED! driver^(s^) in %OUT%\^<arch^>\nanochrono.sys
echo    load:  sc create nanochrono type= kernel binPath= "%CD%\%OUT%\x64\nanochrono.sys"
echo           sc start nanochrono
endlocal
