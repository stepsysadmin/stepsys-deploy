# Preparations
# This is required for Windows 10 IoT Enterprise LTSC
####### 
# Fix Windows Store
wsreset -i
# Run Asheroto's WinGet fixer script
irm https://github.com/asheroto/winget-install/releases/latest/download/winget-install.ps1 | iex
#### Apply registry tweaks that I deem essential
### Customization
# Verbose logon messages
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v VerboseStatus /t REG_DWORD /d 1 /f
# Disable auto correct
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\TabletTip\1.7 /v EnableAutocorrection /t REG_DWORD /d 0 /f
# Disable highlight misspelled words
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\TabletTip\1.7 /v EnableSpellchecking /t REG_DWORD /d 0 /f
# Set device usage mode to GAMING!!!
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Intent\gaming /v Intent /t REG_DWORD /d 1 /f
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Intent\gaming /v Priority /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Intent\OffDeviceConsent /v accepted /t REG_DWORD /d 1 /f
# Enable Win32 long paths
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f
# Show file extensions by default on
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f
### Performance
# Disable Hardware accelerated GPU scheduling because it causes stutters when watching YouTube and playing ETS2 simultaneously
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers /v HwSchMode /t REG_DWORD /d 1 /f
# Optimizations for windowed games
reg add HKEY_CURRENT_USER\Software\Microsoft\DirectX\GraphicsSettings /v SwapEffectUpgradeCache /t REG_DWORD /d 1 /f
reg add HKEY_CURRENT_USER\Software\Microsoft\DirectX\UserGpuPreferences /v DirectXUserGlobalSettings /t REG_SZ /d "SwapEffectUpgradeEnable=1;" /f
# Disable startup delay
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize /v StartupDelayInMSec /t REG_DWORD /d 0 /f
### Privacy
# Disable app launch tracking
reg add HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI /v DisableMFUTracking /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EdgeUI /v DisableMFUTracking /t REG_DWORD /d 1 /f
# Bye bye File History
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\FileHistory /v Disabled /t REG_DWORD /d 1 /f
# Find my Device is no more
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice /v LocationSyncEnabled /t REG_DWORD /d 0 /f
# Disable shared experiences
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System /v EnableCdp /t REG_DWORD /d 0 /f
# Disable ads, reset advertising ID, disable suggestions and disable Windows timeline
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SoftLandingEnabled /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SubscribedContent-310093Enabled /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo /v Enabled /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SubscribedContent-310093Enabled /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System /v EnableActivityFeed /t REG_DWORD /d 0 /f
# Disable Potentially Unwanted Application reporting
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender /v PUAProtection /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine /v MpEnablePus /t REG_DWORD /d 0 /f
### Security
# Enable Windows Defender Core Isolation (Hypervisor-Enforced Code Integrity)
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity /v Enabled /t REG_DWORD /d 1 /f
# Disable Automatic Sample Sumbission in Windows Defender
Set-MpPreference -SubmitSamplesConsent NeverSend​
#######
### Install Tools and useful stuff using WinGet
## Currently includes the following applications:
## 7-zip, Audacity, BCUninstaller, CPU-Z, Discord, Everything, FFmpeg, nomacs, OneDrive, VSCode, NAPS2, GPU-Z, Windows Terminal, VLC, WizTree, yt-dlp
winget install -e --id 7zip.7zip;winget install -e --id Audacity.Audacity;winget install -e --id Klocman.BulkCrapUninstaller;winget install -e --id CPUID.CPU-Z;winget install -e --id Discord.Discord;winget install -e --id voidtools.Everything;winget install -e --id Gyan.FFmpeg;winget install -e --id Microsoft.OneDrive;winget install -e --id Microsoft.VisualStudioCode;winget install -e --id Cyanfish.NAPS2;winget install -e --id TechPowerUp.GPU-Z;winget install -e --id Microsoft.WindowsTerminal;winget install -e --id VideoLAN.VLC;winget install -e --id AntibodySoftware.WizTree;winget install -e --id Mozilla.Firefox;winget install -e --id nomacs.nomacs;winget install -e --id yt-dlp.yt-dlp
