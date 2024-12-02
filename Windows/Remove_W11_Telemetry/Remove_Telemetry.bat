@echo off
echo ---------------------------------------------------
echo        Complete Removal of Windows 11 Telemetry
echo ---------------------------------------------------

:: Disable main telemetry services
echo [*] Disabling main telemetry services...
sc stop DiagTrack
sc config DiagTrack start= disabled
sc stop dmwappushservice
sc config dmwappushservice start= disabled
sc stop WerSvc
sc config WerSvc start= disabled
sc stop Wecsvc
sc config Wecsvc start= disabled
sc stop Uploadmgr
sc config Uploadmgr start= disabled
sc stop MicrosoftEdgeUpdate
sc config MicrosoftEdgeUpdate start= disabled
sc stop Dosvc
sc config Dosvc start= disabled

:: Disable diagnostic data collection and feedback
echo [*] Disabling diagnostic data collection and feedback...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotTrack" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableAutomaticAppUpdate" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DisablePrivacy" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoUseStoreAsDefault" /t REG_DWORD /d 1 /f

:: Disable telemetry via Microsoft Store and UWP apps
echo [*] Disabling telemetry from Microsoft Store and UWP apps...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoUseStoreAsDefault" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWindowsStore" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoStoreOpenWith" /t REG_DWORD /d 1 /f

:: Disable Cortana data collection
echo [*] Disabling Cortana data collection...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f

:: Disable synchronization of data and settings
echo [*] Disabling synchronization of data and settings...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SyncCenter" /v "SyncEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SyncCenter" /v "BackgroundSync" /t REG_DWORD /d 0 /f

:: Disable geolocation
echo [*] Disabling geolocation...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Location" /v "Disabled" /t REG_DWORD /d 1 /f

:: Disable telemetry for Windows Defender
echo [*] Disabling telemetry for Windows Defender...
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "DisableCatchup" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "DisableErrorReporting" /t REG_DWORD /d 1 /f

:: Disable additional advanced telemetry and feedback
echo [*] Disabling additional advanced telemetry and feedback...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feedback" /v "DoNotAskForFeedback" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feedback" /v "NoFeedback" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feedback" /v "FeedbackFrequency" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feedback" /v "IsUserConsentGiven" /t REG_DWORD /d 0 /f

:: Disable automatic error data collection
echo [*] Disabling automatic error data collection...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ErrorReporting" /v "DoNotSendData" /t REG_DWORD /d 1 /f

:: Disable telemetry regarding app updates
echo [*] Disabling telemetry regarding app updates...
reg add "HKLM\Software\Policies\Microsoft\Windows\Store" /v "AutoDownload" /t REG_DWORD /d 0 /f

:: Disable advanced Microsoft synchronization features
echo [*] Disabling advanced Microsoft synchronization features...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Sync" /v "Enable" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Sync" /v "EnableSync" /t REG_DWORD /d 0 /f

:: Disable telemetry for Microsoft Edge
echo [*] Disabling telemetry for Microsoft Edge...
reg add "HKCU\Software\Microsoft\Edge\Profile" /v "EnableTelemetry" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Edge\Profile" /v "EnableWebViewTelemetry" /t REG_DWORD /d 0 /f

:: Disable advanced diagnostic data collection in Windows 11
echo [*] Disabling advanced diagnostic data collection in Windows 11...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDiagnostic" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoTelemetry" /t REG_DWORD /d 1 /f

:: Disable data collection from Windows Update
echo [*] Disabling data collection from Windows Update...
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdate" /t REG_DWORD /d 1 /f

:: Disable data collection from Microsoft
echo [*] Disabling data collection from Microsoft...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Customer Experience Improvement Program" /v "CEIPEnabled" /t REG_DWORD /d 0 /f

:: Disable diagnostic event logging
echo [*] Disabling diagnostic event logging...
reg add "HKLM\System\CurrentControlSet\Services\eventlog" /v "DisableEventLog" /t REG_DWORD /d 1 /f

:: Disable telemetry from third-party apps
echo [*] Disabling telemetry from third-party apps...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoThirdPartyTelemetry" /t REG_DWORD /d 1 /f

:: Disable Feedback Hub functionality
echo [*] Disabling Feedback Hub functionality...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoFeedbackHub" /t REG_DWORD /d 1 /f

echo ---------------------------------------------------
echo Telemetry has been successfully removed.
echo Some changes may require a restart to take effect.
pause
