cd %systemroot%\system32
sc stop VSS
sc config VSS start= demand
sc start VSS
sc stop Volume Shadow Copy
sc config Volume Shadow Copy start= demand
sc stop swprv
sc config swprv start= demand
sc start swprv
sc stop Microsoft Software Shadow Copy Provider
sc config Microsoft Software Shadow Copy Provider start= demand
sc start Microsoft Software Shadow Copy Provider
taskkill /IM "explorer.exe" /f
taskkill /IM "Taskmgr.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d 0 /f
powershell -ExecutionPolicy Unrestricted -NoProfile Enable-ComputerRestore -Drive 'C:\', 'D:\', 'E:\', 'F:\', 'G:\'
powershell -ExecutionPolicy Unrestricted -NoProfile Checkpoint-Computer -Description 'Nexus Tweaking Utility'
timeout /t 1 & cls
del /s /f /q %Temp%\*.*
for /f %%f in ('dir /ad /b %Temp%\') do rd /s /q %Temp%\%%f