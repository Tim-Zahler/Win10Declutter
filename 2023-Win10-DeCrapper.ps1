#################################
# 2023 Windows 10 Privacy Script v2.0
# Authored by T. Zahler
# with some help of ChatGPT, thanks a lot! ;)
# 
# Got Questions? Mail: info@timzahler.ch
#
# USE OF THIS SCRIPT AT YOUR OWN RISK!!!
#
##################################



# Ask for elevated permission
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}




##############
# Privacy Settings
##############

# Remove THAT F***ING KEYLOGGER FROM MY SYSTEM!!!!!!!
Write-Host "Removing the Microsoft Keylogger..."
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /t REG_DWORD /d "1"
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "2"

# Disable Telemetry
Write-Host "Disabling Telemetry..."
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

# Disable Wi-Fi Sense
Write-Host "Disabling Wi-Fi Sense..."
If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
	New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

# Disable Location Tracking
Write-Host "Disabling Location Tracking..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

# Disable Feedback
Write-Host "Disabling Feedback..."
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
	New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0

# Disable Unique Advertising ID
Write-Host "Disabling Advertising ID..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0

# Remove AutoLogger file and restrict directory
Write-Host "Removing AutoLogger file and restricting directory..."
$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
	Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
}
icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

# Stop and disable Diagnostics Tracking Service
Write-Host "Stopping and disabling Diagnostics Tracking Service..."
Stop-Service "DiagTrack"
Set-Service "DiagTrack" -StartupType Disabled

# Disable Autorun for all drives
 Write-Host "Disabling Autorun for all drives..."
 If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
}
 Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255







################
# Remove/Disable unwanted Windows Services
#
# This script disables unwanted Windows services. If you do not want to disable
# certain services comment out the corresponding lines below
###############

$services = @(
    "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"                                # Diagnostics Tracking Service
    "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
    "lfsvc"                                    # Geolocation Service
    "MapsBroker"                               # Downloaded Maps Manager
    "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
    "RemoteAccess"                             # Routing and Remote Access
    # "RemoteRegistry"                         # Remote Registry
    "SharedAccess"                             # Internet Connection Sharing (ICS)
    "TrkWks"                                   # Distributed Link Tracking Client
    #"WbioSrvc"                                # Windows Biometric Service (required for Fingerprint reader / facial detection)
    #"WlanSvc"                                 # WLAN AutoConfig
    "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
    #"wscsvc"                                  # Windows Security Center Service
    #"WSearch"                                 # Windows Search
    "XblAuthManager"                           # Xbox Live Auth Manager
    "XblGameSave"                              # Xbox Live Game Save Service
    "XboxNetApiSvc"                            # Xbox Live Networking Service
    "ndu"                                      # Windows Network Data Usage Monitor
)

foreach ($service in $services) {
    Write-Output "Trying to disable $service"
    Get-Service -Name $service | Set-Service -StartupType Disabled
}

# Disable Advertising ID
Write-Host "Disabling Advertising ID..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0

# Disable sharing mapped drives between users
Write-Host "Disable sharing mapped drives between users..."
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections"

# Uninstall default Microsoft applications
$apps = @(
"Disney+"
"Microsoft.Paint3D"
"Microsoft.PCHealthCheck"
"Microsoft.MicrosoftStickyNotes"
"Microsoft.XboxGameOverlay"
"Microsoft.SkypeApp"
)

ForEach ($app in $apps) {
    $package = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue
    if ($package -ne $null) {
        Write-Host "Uninstalling $($package.Name)..."
        Remove-AppxPackage -Package $package.PackageFullName -AllUsers
    } else {
        Write-Host "$app not found, skipping..."
    }
}

# Disable windows update seeding other computers
Write-Output "Disable seeding of updates to other computers via Group Policies"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "DODownloadMode" -Value 0




####################
# UI Tweaks
####################

# Hide Task View
Write-Host "Disabling Task View Button..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0

# Hide Search button / box
Write-Host "Hiding Search Box / Button..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

# Hide/Disable the News Section
Write-Host "Hiding the News Section..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 1

# Disable Sticky keys prompt
Write-Host "Disabling Sticky keys prompt..."
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"

# Unset taskbar button grouping
Write-Host "Setting Taskbar Buttons to Ungrouped..."
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "TaskbarGlomLevel" -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "TaskbarGlomLevelPerDisplay" -Type DWord -Value 0

# Show all tray icons
Write-Host "Showing all tray icons..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0

# Change default Explorer view to "Computer"
Write-Host "Setting default Explorer view to Computer..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage2" -Name "Custom" -Value "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

# Enable Windows Snapping Feature
Write-Host "Enabling Snapping Feature..."
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "SnapToDefaultProgram" -Type DWord -Value 1

# Disable Snap feature that shows what can be snapped (frigging annyoing thing)
Write-Host "Disabling showing what can be snapped when snapping..."
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "SnapToDefaultProgram" -Type DWord -Value 0


# Set Photo Viewer as default for bmp, gif, jpg and png
Write-Host "Setting Photo Viewer as default for bmp, gif, jpg, png and tif..."
If (!(Test-Path "HKCR:")) {
	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
	New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
	New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
	Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
	Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
}

# Show Photo Viewer in "Open with..."
Write-Host "Showing Photo Viewer in `"Open with...`""
If (!(Test-Path "HKCR:")) {
	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"

# Remove all Tiles from Start Menu
Write-Host "Removing all Tiles from Start Menu..."
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*" -Recurse -Force

# Set Windows to Dark Mode
Write-Host "Setting Windows to Dark Mode..."
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name "AppsUseLightTheme" -Type DWord -Value 0

# Disable Bing Search in Start Menu
Write-Host "Disabling Bing Search in Start Menu..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0

# Disable Location Tracking
Write-Host "Disabling Location Tracking..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

# Add Powershell & CMD "Open Here" to Context Menu
$text = @"
Windows Registry Editor Version 5.00

; Command Prompt

[HKEY_CLASSES_ROOT\Directory\shell\01MenuCmd]
"MUIVerb"="Command Prompts"
"Icon"="cmd.exe"
"ExtendedSubCommandsKey"="Directory\\ContextMenus\\MenuCmd"

[HKEY_CLASSES_ROOT\Directory\background\shell\01MenuCmd]
"MUIVerb"="Command Prompts"
"Icon"="cmd.exe"
"ExtendedSubCommandsKey"="Directory\\ContextMenus\\MenuCmd"

[HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuCmd\shell\open]
"MUIVerb"="Command Prompt"
"Icon"="cmd.exe"

[HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuCmd\shell\open\command]
@="cmd.exe /s /k pushd \"%V\""

[HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuCmd\shell\runas]
"MUIVerb"="Command Prompt Elevated"
"Icon"="cmd.exe"
"HasLUAShield"=""

[HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuCmd\shell\runas\command]
@="cmd.exe /s /k pushd \"%V\""


; PowerShell

[HKEY_CLASSES_ROOT\Directory\shell\02MenuPowerShell]
"MUIVerb"="PowerShell Prompts"
"Icon"="powershell.exe"
"ExtendedSubCommandsKey"="Directory\\ContextMenus\\MenuPowerShell"

[HKEY_CLASSES_ROOT\Directory\background\shell\02MenuPowerShell]
"MUIVerb"="PowerShell Prompts"
"Icon"="powershell.exe"
"ExtendedSubCommandsKey"="Directory\\ContextMenus\\MenuPowerShell"

[HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPowerShell\shell\open]
"MUIVerb"="PowerShell"
"Icon"="powershell.exe"

[HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPowerShell\shell\open\command]
@="powershell.exe -noexit -command Set-Location '%V'"

[HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPowerShell\shell\runas]
"MUIVerb"="PowerShell Elevated"
"Icon"="powershell.exe"
"HasLUAShield"=""

[HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPowerShell\shell\runas\command]
@="powershell.exe -noexit -command Set-Location '%V'"


; Ensure OS Entries are on the Extended Menu (Shift-Right Click)

[HKEY_CLASSES_ROOT\Directory\shell\cmd]
"Extended"=""

[HKEY_CLASSES_ROOT\Directory\background\shell\cmd]
"Extended"=""

[HKEY_CLASSES_ROOT\Directory\shell\Powershell]
"Extended"=""

[HKEY_CLASSES_ROOT\Directory\background\shell\Powershell]
"Extended"=""
"@

Set-Content -Path "MenuGit.reg" -Value $text -Force
Start-Process "regedit.exe" "/s MenuGit.reg"



##########
# Random other Stuff i like
##########

# Set Windows to High Performance Mode
Write-Host "Setting Windows to High Performance Mode..."
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

# Activate Cipboard History (using Win + V)
Write-Host "Activating Clipboard History (Use Win + V to View)..."
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "EnableClipboardHistory" -Type DWord -Value 1

# Mount CD Drive by default as A:
Write-Host "Mount CD Drive by default as A:"
New-PSDrive -Name "A" -Root "\\.\CDROM" -PSProvider FileSystem

# Activate Network Discovery to mount Network Shares
Write-Host "Activating Network Discovery to mount Network Shares..."
Set-NetFirewallProfile -Profile Domain,Private -Enabled True

# Set Notifications to Alerts only
Write-Host "Setting Notifications to Alerts only..."
Set-ItemProperty -Path "HKCU:\Control Panel\Notifications" -Name "ToastEnabled" -Value 1




##########
# Install Common Applications
##########

# Install Chrome
Write-Host "Installing Chrome..."
Invoke-WebRequest -Uri https://dl.google.com/chrome/install/googlechromestandalone.msi -OutFile chrome.msi; Start-Process -FilePath msiexec.exe -ArgumentList '/i chrome.msi /quiet /norestart' -Wait

#Set Chrome as default
Write-Host "Trying to set Chrome as default Browser..."
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' -Name "Progid" -PropertyType String -Value "ChromeHTML"

# Install Firefox
Write-Host "Installing Firefox..."
Invoke-WebRequest -Uri https://download.mozilla.org/?product=firefox-latest-ssl&os=win&lang=en-US -OutFile firefox.exe; Start-Process -FilePath firefox.exe -ArgumentList '/S' -Wait

# Install Extensions for Firefox
Wirte-Host "Installing Firefox Extensions: Adblocker & Tab Session Manager..."
Invoke-WebRequest -Uri "https://install.adblockplus.org/windows/abp.xpi" -OutFile "$env:TEMP\abp.xpi"
Start-Process "firefox.exe" -ArgumentList "$env:TEMP\abp.xpi"
Invoke-WebRequest -Uri "https://addons.mozilla.org/firefox/downloads/file/3630357/tab_session_manager-1.3.3-an+fx.xpi" -OutFile "$env:TEMP\tab_session_manager.xpi"
Start-Process "firefox.exe" -ArgumentList "$env:TEMP\tab_session_manager.xpi"

# Install Greenshot
Write-Host "Installing Greenshot..."
Invoke-WebRequest -Uri https://get.greenshot.org/install/stable/Greenshot-INSTALLER-1.2.10.6.exe -OutFile Greenshot.exe; Start-Process -FilePath Greenshot.exe -ArgumentList '/S' -Wait

# Install KeePass
Write-Host "Installing KeePass..."
Invoke-WebRequest -Uri https://keepass.info/download/KeePass-2.47.zip -OutFile KeePass.zip; Expand-Archive -Path KeePass.zip -DestinationPath KeePass; Start-Process -FilePath KeePass\KeePass.exe -Wait

# Install Teamviewer
Write-Host "Installing Teamviewer..."
Invoke-WebRequest -Uri https://download.teamviewer.com/download/TeamViewer_Setup.exe -OutFile TeamViewer.exe; Start-Process -FilePath TeamViewer.exe -ArgumentList '/S' -Wait

# Setup Teamviewer with config file
Write-Host "Trying to configure Teamviewer with default Settings..."
    # Install the TeamViewer PowerShell module
    Install-Module -Name TeamViewer
    # Import the TeamViewer module
    Import-Module -Name TeamViewer

    # Set the desired settings using the TeamViewer cmdlets
    Set-TeamViewerAccount -Email "user@example.com" -Password "MyPassword"
    Set-TeamViewerConnection -ProxyType "None" -Port 5939
    Set-TeamViewerGUI -ShowTrayIcon $true

# Install VLC Media Player
Write-Host "Installing VLC Media Player..."
Invoke-WebRequest -Uri https://get.videolan.org/vlc/3.0.11/win64/vlc-3.0.11-win64.exe -OutFile vlc.exe; Start-Process -FilePath vlc.exe -ArgumentList '/S' -Wait



#########################
#
# Restart Computer
#
#########################
Write-Host "Restarting Computer in 5 Seconds..."
$countdown = 5

while ($countdown -gt 0) {
    Write-Host "Restarting in: $countdown"
    Start-Sleep -Seconds 1
    $countdown--
}
Restart-Computer
