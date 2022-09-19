# Need to be fixed list:
##  Empty..


# Install chocolatey
    Add-Type -AssemblyName System.Windows.Forms
    $global:balloon = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balloon.BalloonTipText = 'Windows Settings'
    $balloon.BalloonTipTitle = "Installing chocolatey" 
    $balloon.Visible = $true 
    $balloon.ShowBalloonTip(50000)

    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    
    Start-Sleep -s 3

# Install desktop applications

        # installing Google Chrome 
            Add-Type -AssemblyName System.Windows.Forms
            $global:balloon = New-Object System.Windows.Forms.NotifyIcon
            $path = (Get-Process -id $pid).Path
            $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
            $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
            $balloon.BalloonTipText = 'Google Chrome'
            $balloon.BalloonTipTitle = "Installing Chrome..." 
            $balloon.Visible = $true 
            $balloon.ShowBalloonTip(50000)

            choco install googlechrome -y --ignore-checksums --force | out-null
                # BUG FIX: Transparent dropdown menu
                If (!(Test-Path "HKLM:\SOFTWARE\Policies\Google\Chrome\")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\" -Force | Out-Null}
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\" -Name "HardwareAccelerationModeEnabled" -Type DWord -Value 0
                # Add Ublock Origin Adblocker Extension
                (New-Object System.Net.WebClient).DownloadFile("https://bitbucket.org/svalding/psbrowserextensions/raw/88b200bad8845acbb91d19fdc96cf9dee0303253/New-ChromeExtension.ps1","$env:TMP/chrome-extensions.ps1")
                Import-Module "$env:TMP/chrome-extensions.ps1"
                New-ChromeExtension -ExtensionID 'cjpalhdlnbpafiamejdnhcphjbkeiagm' -Hive Machine
            
            Start-Sleep -s 3
            
        # Installing Adobe Acrobat Reader
            Add-Type -AssemblyName System.Windows.Forms
            $global:balloon = New-Object System.Windows.Forms.NotifyIcon
            $path = (Get-Process -id $pid).Path
            $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
            $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
            $balloon.BalloonTipText = 'Adobe Acrobat Reader'
            $balloon.BalloonTipTitle = "Installing Adobe Reader..." 
            $balloon.Visible = $true 
            $balloon.ShowBalloonTip(50000)
            choco install adobereader -y
            
            Start-Sleep -s 3
            
        # Installing VLC
            Add-Type -AssemblyName System.Windows.Forms
            $global:balloon = New-Object System.Windows.Forms.NotifyIcon
            $path = (Get-Process -id $pid).Path
            $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
            $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
            $balloon.BalloonTipText = 'VLC Media player'
            $balloon.BalloonTipTitle = "Installing VLC..." 
            $balloon.Visible = $true 
            $balloon.ShowBalloonTip(50000)
            choco install VLC -y
            
            Start-Sleep -s 3

        # Installing 7-Zip
            Add-Type -AssemblyName System.Windows.Forms
            $global:balloon = New-Object System.Windows.Forms.NotifyIcon
            $path = (Get-Process -id $pid).Path
            $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
            $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
            $balloon.BalloonTipText = '7-zip'
            $balloon.BalloonTipTitle = "Installing 7-zip..." 
            $balloon.Visible = $true 
            $balloon.ShowBalloonTip(50000)
            choco install 7Zip -y
            
            Start-Sleep -s 3
            
   
# Cleaning windows 

    # Unpin start menu

    Add-Type -AssemblyName System.Windows.Forms
    $global:balloon = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balloon.BalloonTipText = 'Windows Settings'
    $balloon.BalloonTipTitle = "Unpinning apps.." 
    $balloon.Visible = $true 
    $balloon.ShowBalloonTip(50000)

    $layoutFile = "$env:SystemRoot\StartMenuLayout.xml"
    $layoutFile_new = (Invoke-WebRequest -uri "https://raw.githubusercontent.com/Andreas6920/deploy-project/main/resources/StartMenyLayout.xml" -UseBasicParsing).content    
    
    Start-Sleep 3
    
        # Delete layout file if it already exists
            If (Test-Path $layoutFile) { Remove-Item $layoutFile }   

        # Creates the blank layout file
            Write-host "        - Creates and applying a new blank start menu..." -f Yellow
            $layoutFile_new | Out-File $layoutFile -Encoding ASCII
            $regAliases = @("HKLM", "HKCU")

        # Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
            foreach ($regAlias in $regAliases) {
            $basePath = $regAlias + ":\Software\Policies\Microsoft\Windows"
            $keyPath = $basePath + "\Explorer" 
            IF (!(Test-Path -Path $keyPath)) {  New-Item -Path $basePath -Name "Explorer" | Out-Null }
            Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
            Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile }

        # Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
            Write-host "        - Restarting explorer..." -f yellow
            Stop-Process -name explorer -Force
            Start-Sleep -s 5

        # Enable the ability to pin items again by disabling "LockedStartLayout"
            foreach ($regAlias in $regAliases) {
                $basePath = $regAlias + ":\Software\Policies\Microsoft\Windows"
                $keyPath = $basePath + "\Explorer" 
                Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0}
            Stop-Process -name explorer
            Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\
            Remove-Item $layoutFile

            Start-Sleep -S 3;

    # unpin Taskbar

        Add-Type -AssemblyName System.Windows.Forms
        $global:balloon = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
        $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balloon.BalloonTipText = 'Windows Settings'
        $balloon.BalloonTipTitle = "Unpinning Taskbar.." 
        $balloon.Visible = $true 
        $balloon.ShowBalloonTip(50000)

        Start-Sleep -s 3
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesChanges -Value 3 -Type Dword -Force | Out-Null
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesRemovedChanges -Value 32 -Type Dword -Force | Out-Null
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesVersion -Value 3 -Type Dword -Force | Out-Null
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name Favorites -Value ([byte[]](0xFF)) -Force | Out-Null
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowCortanaButton -Type DWord -Value 0 | Out-Null
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -Value 0 -Type Dword | Out-Null
        set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -Type DWord -Value 0 | Out-Null
        Remove-Item -Path "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*" -Recurse -Force | Out-Null
        Stop-Process -name explorer
        Start-Sleep -s 1

    # Removing Microsoft Bloat

        Add-Type -AssemblyName System.Windows.Forms
        $global:balloon = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
        $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balloon.BalloonTipText = 'Windows Settings'
        $balloon.BalloonTipTitle = "Uninstalling bloatware.." 
        $balloon.Visible = $true 
        $balloon.ShowBalloonTip(50000)

        $ProgressPreference = "SilentlyContinue" #hide progressbar
        Start-Sleep 3
        $Bloatware = @(

        ## Microsoft Bloat ##
        "*autodesksketch*"
        "*oneconnect*"
        "*plex*"
        "*print3d*"
        "Microsoft.3DBuilder"
        "Microsoft.Getstarted"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.Office.OneNote"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.MicrosoftStickyNotes"
        "Microsoft.MixedReality.Portal"
        "Microsoft.Music.Preview"
        "Microsoft.People"
        "Microsoft.PeopleExperienceHost"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsMaps"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        "Microsoft.windowscommunicationsapps"
        "Microsoft.Wallet"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "CBSPreview"
                                            
        ## Xbox Bloat ##
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxApp"
        "Microsoft.XboxGameCallableUI"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxGamingOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
                                            
        ## Bing Bloat ##
        "*Bing*"
        "Microsoft.Bing*"
        "Microsoft.BingFinance"
        "Microsoft.BingFoodAndDrink"
        "Microsoft.BingHealthAndFitness"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingTravel"
        "Microsoft.BingWeather"

        ## Games ##
        "*Bubblewitch*"
        "*Candycrush*"
        "*Disney*"
        "*Empires*"
        "*Minecraft*"
        "*Royal revolt*"
                            
        ## Other crap ##
        "*Disney*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*EclipseManager*"
        "*Facebook*"
        "*Flipboard*"
        "*PandoraMediaInc*"
        "*Skype*"
        "*Spotify*"
        "*Twitter*"
        "*Wunderlist*"
        )
        
        foreach ($Bloat in $Bloatware) {
            Get-AppxPackage -Name $Bloat | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null}

    # Disabling services

        Add-Type -AssemblyName System.Windows.Forms
        $global:balloon = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
        $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balloon.BalloonTipText = 'Windows Settings'
        $balloon.BalloonTipTitle = "Cleaning service.." 
        $balloon.Visible = $true 
        $balloon.ShowBalloonTip(50000)
    
        Start-Sleep -s 3
        $services = @(
            "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
            "DiagTrack"                                # Diagnostics Tracking Service
            "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
            "lfsvc"                                    # Geolocation Service
            "MapsBroker"                               # Downloaded Maps Manager
            "ndu"                                      # Windows Network Data Usage Monitor
            "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
            "RemoteAccess"                             # Routing and Remote Access
            "RemoteRegistry"                           # Remote Registry
            "SharedAccess"                             # Internet Connection Sharing (ICS)
            "TrkWks"                                   # Distributed Link Tracking Client
            "WbioSrvc"                                 # Windows Biometric Service (required for Fingerprint reader / facial detection)
            "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
            "XblAuthManager"                           # Xbox Live Auth Manager
            "XblGameSave"                              # Xbox Live Game Save Service
            "XboxNetApiSvc"                            # Xbox Live Networking Service
            )

        foreach ($service in $services) {
        if((Get-Service -Name $service | Where-Object Starttype -ne Disabled)){
        Get-Service | Where-Object name -eq $service | Set-Service -StartupType Disabled}}
        Start-Sleep -S 3;

    # Clean Task Scheduler

        Add-Type -AssemblyName System.Windows.Forms
        $global:balloon = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
        $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balloon.BalloonTipText = 'Windows Settings'
        $balloon.BalloonTipTitle = "Cleaning task scheduler.." 
        $balloon.Visible = $true 
        $balloon.ShowBalloonTip(50000)
    
        Start-Sleep -s 3
        $Bloatschedules = @(
            "AitAgent" 
            "AnalyzeSystem" 
            "Automatic App Update" 
            "BthSQM" 
            "Consolidator"
            "Consolidator" 
            "CreateObjectTask" 
            "Diagnostics" 
            "DmClient"
            "DmClientOnScenarioDownload"
            "DsSvcCleanup" 
            "EnableLicenseAcquisition" 
            "FamilySafetyMonitor" 
            "FamilySafetyMonitorToastTask" 
            "FamilySafetyRefresh" 
            "FamilySafetyRefreshTask" 
            "FamilySafetyUpload" 
            "File History (maintenance mode)" 
            "GatherNetworkInfo" 
            "KernelCeipTask" 
            "License Validation" 
            "LicenseAcquisition" 
            "LoginCheck" 
            "Microsoft Compatibility Appraiser" 
            "Microsoft-Windows-DiskDiagnosticDataCollector" 
            "ProgramDataUpdater" 
            "Proxy" 
            "QueueReporting" 
            "RecommendedTroubleshootingScanner" 
            "Registration" 
            "Scheduled" 
            "SmartScreenSpecific" 
            "Sqm-Tasks" 
            "StartupAppTask" 
            "TempSignedLicenseExchange" 
            "Uploader" 
            "UsbCeip"
            "UsbCeip" 
            "WinSAT" 
            "XblGameSaveTask")

            foreach ($BloatSchedule in $BloatSchedules) {
            if ((Get-ScheduledTask | Where-Object state -ne Disabled | Where-Object TaskName -like $BloatSchedule)){
            Get-ScheduledTask | Where-Object Taskname -eq $BloatSchedule | Disable-ScheduledTask | Out-Null}}
            Start-Sleep -S 3;

    # Cleaning printers
        Add-Type -AssemblyName System.Windows.Forms
        $global:balloon = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
        $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balloon.BalloonTipText = 'Windows Settings'
        $balloon.BalloonTipTitle = "Cleaning printers.." 
        $balloon.Visible = $true 
        $balloon.ShowBalloonTip(50000)
    
        # Disabling auto-install printers from network
        If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null}
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
        
        # Cleaning spooler
        Stop-Service "Spooler" | out-null; sleep -s 3
        Remove-Item "$env:SystemRoot\System32\spool\PRINTERS\*.*" -Force | Out-Null
        Start-Service "Spooler"

        # Removing bloat printers
        $Bloatprinters = "Fax","OneNote for Windows 10","Microsoft XPS Document Writer", "Microsoft Print to PDF" 
        $Bloatprinters | % {if(Get-Printer | Where-Object Name -cMatch $_){Write-Host "`t`t`t- Uninstalling: $_" -f Yellow; Remove-Printer $_; Start-Sleep -s 2}}
        Start-Sleep -S 3;

    # Privacy settings
        Add-Type -AssemblyName System.Windows.Forms
        $global:balloon = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
        $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balloon.BalloonTipText = 'Windows Settings'
        $balloon.BalloonTipTitle = "Improving privacy settings.." 
        $balloon.Visible = $true 
        $balloon.ShowBalloonTip(50000)

        # Disable Advertising ID
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
            Start-Sleep -s 2
    
        # Disable let websites provide locally relevant content by accessing language list
            If (!(Test-Path "HKCU:\Control Panel\International\User Profile")) {
                New-Item -Path "HKCU:\Control Panel\International\User Profile" -Force | Out-Null}
            Set-ItemProperty -Path  "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut"  -Value 1
            Start-Sleep -s 2
    
        # Disable Show me suggested content in the Settings app
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
            Start-Sleep -s 2
    
        # Remove Cortana
            Get-AppxPackage -name *Microsoft.549981C3F5F10* | Remove-AppxPackage
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
            Stop-Process -name explorer
            Start-Sleep -s 5

        # Disable Online Speech Recognition
            If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
                New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 0
            Start-Sleep -s 2
    
        # Hiding personal information from lock screen
            If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System")) {
                New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Force | Out-Null}
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayLockedUserID" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayLastUsername" -Type DWord -Value 0
            Start-Sleep -s 2
    
        # Disable diagnostic data collection
            If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection")) {
                New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null}
            Set-ItemProperty -Path  "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"  -Value 0
            Start-Sleep -s 2
    
        # Disable App Launch Tracking
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "Start_TrackProgs" -Type DWord -Value 0
            Start-Sleep -s 2

        # Disable "tailored expirence"
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy")) {   
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Force | Out-Null}
            Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled"  -Value 0
            Start-Sleep -s 2
    
    # Security settings
        Add-Type -AssemblyName System.Windows.Forms
        $global:balloon = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
        $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balloon.BalloonTipText = 'Windows Settings'
        $balloon.BalloonTipTitle = "Improving security settings.." 
        $balloon.Visible = $true 
        $balloon.ShowBalloonTip(50000)           
            
        # Disable automatic setup of network connected devices.
            If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null}
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0 -Force 
            Start-Sleep -s 2
        
        # Disable sharing of PC and printers
            Get-NetConnectionProfile | ForEach-Object {Set-NetConnectionProfile -Name $_.Name -NetworkCategory Public -ErrorAction SilentlyContinue | Out-Null}    
            get-printer | Where-Object shared -eq True | ForEach-Object {Set-Printer -Name $_.Name -Shared $False -ErrorAction SilentlyContinue | Out-Null}
            netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -s 2

        # Disable LLMNR    
            #https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
            New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT\" -Name "DNSClient" -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 0 -Force -ea SilentlyContinue | Out-Null
            Start-Sleep -s 2

        # Bad Neighbor - CVE-2020-16898 (Disable IPv6 DNS)  
            # https://blog.rapid7.com/2020/10/14/there-goes-the-neighborhood-dealing-with-cve-2020-16898-a-k-a-bad-neighbor/
            # Disable DHCPv6  + routerDiscovery
            Set-NetIPInterface -AddressFamily IPv6 -InterfaceIndex $(Get-NetIPInterface -AddressFamily IPv6 | Select-Object -ExpandProperty InterfaceIndex) -RouterDiscovery Disabled -Dhcp Disabled
            # Prefer IPv4 over IPv6 (IPv6 is prefered by default)
            If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters")) {
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Force | Out-Null}
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Type DWord -Value 0x20 -Force
            Start-Sleep -s 2

        # Disabe SMB Compression - CVE-2020-0796    
            # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0796
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force -ea SilentlyContinue | Out-Null
            Start-Sleep -s 2

        # Disable SMB v1    
            # https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            start-job -Name "Disable SMB1" -ScriptBlock {
            Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart -WarningAction:SilentlyContinue | Out-Null
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force} | Out-Null
            Start-Sleep -s 2

        # Disable SMB v2    
            # https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 0 –Force
            Start-Sleep -s 2

        # Enable SMB Encryption    
            # https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security
            Set-SmbServerConfiguration –EncryptData $true -Force -ea SilentlyContinue | Out-Null
            Set-SmbServerConfiguration –RejectUnencryptedAccess $false -Force -ea SilentlyContinue | Out-Null
            Start-Sleep -s 2
            
        # Spectre Meldown - CVE-2017-5754    
            # https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type DWORD -Value 3 -Force -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -Type String -Value "1.0" -Force -ea SilentlyContinue | Out-Null
            Start-Sleep -s 2
           
        
    # Other beneficial settings
    
        # Show file extensions
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
            
        # Change Explorer to "This PC"
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
        
        # Start Menu: Disable Bing Search Results
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
        
        # Remove login screensaver - preventing missing first character
            If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization")) {
                New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "Personalization" | Out-Null}
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1
        
        # Skip IE first run wizard
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null}
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1

        # Set Photo Viewer association for bmp, gif, jpg, png and tif
            If (!(Test-Path "HKCR:")) {
                New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null}
            ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
            New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
            New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
            Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
            Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"}
        
        # Show seconds in taskbar
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Type DWord -Value 1
            Stop-Process -name explorer; Start-Sleep -s 3

        # Setting DNS
            $newDNS = ("1.1.1.1", "1.0.0.1") # Cloudflare DNS server
            $ethernetadaptername = (Get-NetAdapter | Where-Object {-not $_.Virtual -and $_.Status -eq 'up'}).Name
            Set-DnsClientServerAddress -InterfaceAlias $ethernetadaptername -ServerAddresses $newDNS; Start-Sleep -s 2
            ipconfig /flushdns; Start-Sleep -s 2

        # Create an chocolatey app-updater
            if ((Get-Childitem -Path $env:ProgramData).Name  -match "Chocolatey"){
                #create update file
                $filepath = "$env:ProgramData\chocolatey\app-updater.ps1"
                Invoke-WebRequest -uri "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/app-updater/app-updater.ps1" -OutFile $filepath -UseBasicParsing
                # Create scheduled job
                $name = 'App-updater'
                $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-nop -W hidden -noni -ep bypass -file $filepath"
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM"-LogonType ServiceAccount -RunLevel Highest
                $trigger= New-ScheduledTaskTrigger -At 12:00 -Daily
                
                Register-ScheduledTask -TaskName $name -Principal $principal -Action $action -Trigger $trigger -Force | Out-Null}
            else {Write-host "Chocolatey is not installed on this system." -f red}  

    # Create restore point
        Add-Type -AssemblyName System.Windows.Forms
        $global:balloon = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
        $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balloon.BalloonTipText = 'Windows Settings'
        $balloon.BalloonTipTitle = "Creating windows restore point" 
        $balloon.Visible = $true 
        $balloon.ShowBalloonTip(50000)
        Enable-ComputerRestore -Drive "C:\"
        Checkpoint-Computer -Description "Windows just installed."