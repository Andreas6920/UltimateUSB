# Install chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force;
    (New-Object System.Net.WebClient).DownloadFile("https://chocolatey.org/install.ps1","$env:TMP/choco-install.ps1")
    # Executing installation file.
    cd $env:TMP; .\choco-install.ps1
    
    Start-Sleep -s 3

        # installing Google Chrome 
            Add-Type -AssemblyName System.Windows.Forms
            $global:balloon = New-Object System.Windows.Forms.NotifyIcon
            $path = (Get-Process -id $pid).Path
            $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
            $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
            $balloon.BalloonTipText = 'Google Chrome Browser'
            $balloon.BalloonTipTitle = "Installing Chrome..." 
            $balloon.Visible = $true 
            $balloon.ShowBalloonTip(50000)
            choco install googlechrome -y | out-null

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
            choco install 7Zip -y | out-null
            
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
            choco install VLC -y | out-null
            
            Start-Sleep -s 3

   
# Cleaning windows 

    # Unpin start menu

        Add-Type -AssemblyName System.Windows.Forms
        $global:balloon = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
        $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balloon.BalloonTipText = 'Windows Settings'
        $balloon.BalloonTipTitle = "Unpinning StartMenu.." 
        $balloon.Visible = $true 
        $balloon.ShowBalloonTip(50000)

        $layoutFile = "$env:SystemRoot\StartMenuLayout.xml"
        $layoutFile_new = (Invoke-WebRequest -uri "https://raw.githubusercontent.com/Andreas6920/deploy-project/main/resources/StartMenyLayout.xml" -UseBasicParsing).content    
        
        Start-Sleep 3
        
        # Delete layout file if it already exists
            If (Test-Path $layoutFile) {    Remove-Item $layoutFile }   

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
            Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
                                                }

        # Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
            Write-host "        - Restarting explorer..." -f yellow
            Stop-Process -name explorer -Force
            Start-Sleep -s 5

        #Enable the ability to pin items again by disabling "LockedStartLayout"
            foreach ($regAlias in $regAliases) {
                $basePath = $regAlias + ":\Software\Policies\Microsoft\Windows"
                $keyPath = $basePath + "\Explorer" 
                Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
            }
            Stop-Process -name explorer
            Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\
            Remove-Item $layoutFile


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

            "Microsoft.ZuneMusic"
            "Microsoft.MicrosoftSolitaireCollection"
            "Microsoft.MicrosoftOfficeHub"
            "Microsoft.Microsoft3DViewer"
            "Microsoft.MicrosoftStickyNotes"
            "Microsoft.Getstarted"
            "Microsoft.Office.OneNote"
            "Microsoft.People"
            "Microsoft.3DBuilder"
            "*officehub*"
            "*feedback*"
            "Microsoft.Music.Preview"
            "Microsoft.WindowsMaps"
            "*windowscommunicationsapps*"
            "*autodesksketch*"
            "*plex*"
            "*print3d*"
            "*Paint3D*"
            "*Mixed*"
            "*oneconnect*"
                                                
            # Xbox Bloat
            "Microsoft.XboxGameCallableUI"
            "Microsoft.XboxSpeechToTextOverlay"
            "Microsoft.XboxGameOverlay"
            "Microsoft.XboxIdentityProvider"
            "Microsoft.XboxGameCallableUI"
            "Microsoft.XboxGamingOverlay"
            "Microsoft.XboxApp"
            "Microsoft.Xbox.TCUI"
                                                
            # Bing Bloat
            "Microsoft.BingTravel"
            "Microsoft.BingHealthAndFitness"
            "Microsoft.BingFoodAndDrink"
            "Microsoft.BingWeather"
            "Microsoft.BingNews"
            "Microsoft.BingFinance"
            "Microsoft.BingSports"
            "Microsoft.Bing*"
            "*Bing*"

            # Games
            "*disney*"
            "*candycrush*"
            "*minecraft*"
            "*bubblewitch*"
            "*empires*"
            "*Royal Revolt*"
                                
            # Other crap
            "*Skype*"
            "*Facebook*"
            "*Twitter*"
            "*Spotify*"
            "*EclipseManager*"
            "*ActiproSoftwareLLC*"
            "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
            "*Duolingo-LearnLanguagesforFree*"
            "*PandoraMediaInc*"
            "*Wunderlist*"
            "*Flipboard*"
        )
        
        foreach ($Bloat in $Bloatware) {
            $bloat_output = Get-AppxPackage | Where-Object Name -Like $Bloat | Select -Property Name; #Write-Host "        - Removing: $bloat_output"
            if ($bloat_output -ne $null) { Write-host "        - Removing: " -f yellow -nonewline; ; write-host "$bloat_output".Split(".")[1].Split("}")[0] -f yellow }
            Get-AppxPackage -Name $Bloat | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null}
        
        Start-Sleep -s 3   
        $Bloatschedules = @(
                "XblGameSaveTaskLogon"
                "XblGameSaveTask"
                "Consolidator"
                "UsbCeip"
                "DmClient"
                "DmClientOnScenarioDownload"
                )
            foreach ($BloatSchedule in $BloatSchedules) {
            if ((Get-ScheduledTask | ? state -ne Disabled | ? TaskName -like $BloatSchedule)){
            Get-ScheduledTask | ? Taskname -eq $BloatSchedule | Disable-ScheduledTask | Out-Null}}   

    # Remove Windows pre-installed bloat printers (Fax, PDF, OneNote) These are almost never used.
        If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
        Get-Printer | ? Name -cMatch "OneNote for Windows 10|Microsoft XPS Document Writer|Microsoft Print to PDF|Fax" | Remove-Printer 

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
        Write-host "        - Disabling advertising ID." -f yellow
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null}
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
        Start-Sleep -s 2

        # Disable let websites provide locally relevant content by accessing language list
        Write-host "        - Disabling location tracking." -f yellow
        If (!(Test-Path "HKCU:\Control Panel\International\User Profile")) {
            New-Item -Path "HKCU:\Control Panel\International\User Profile" -Force | Out-Null}
        Set-ItemProperty -Path  "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut"  -Value 1
        Start-Sleep -s 2

        # Disable Show me suggested content in the Settings app
        Write-host "        - Disabling personalized content suggestions." -f Yellow
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null}
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
        Start-Sleep -s 2

        # Disable Online Speech Recognition
        Write-host "        - Disabling Online Speech Recognition." -f yellow
        If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
            New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null}
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 0
        Start-Sleep -s 2

        # Hiding personal information from lock screen
        Write-host "        - Hiding email and domain information from sign-in screen." -f yellow
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

        # Disable Inking & Typing Personalization
        If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null}
        Set-ItemProperty -Path  "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection"  -Value 1
        Set-ItemProperty -Path  "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection"  -Value 1
        Start-Sleep -s 2


        # Disabling services
        Write-host "      BLOCKING - Tracking startup services" -f green
        $trackingservices = @(
        "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
        "DiagTrack"                                # Diagnostics Tracking Service
        "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
        "lfsvc"                                    # Geolocation Service
        "TrkWks"                                   # Distributed Link Tracking Client
        "XblAuthManager"                           # Xbox Live Auth Manager
        "XblGameSave"                              # Xbox Live Game Save Service
        "XboxNetApiSvc"                            # Xbox Live Networking Service
                            )

        foreach ($trackingservice in $trackingservices) {
        if((Get-Service -Name $trackingservice | ? Starttype -ne Disabled)){
        Get-Service | ? name -eq $trackingservice | Set-Service -StartupType Disabled}}

        # Removing printers
        If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
                New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null}
                Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
                Get-Printer | ? Name -Like * | Remove-Printer -ErrorAction SilentlyContinue
                

        # Adding entries to hosts file

            Add-Type -AssemblyName System.Windows.Forms
            $global:balloon = New-Object System.Windows.Forms.NotifyIcon
            $path = (Get-Process -id $pid).Path
            $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
            $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
            $balloon.BalloonTipText = 'Windows Settings'
            $balloon.BalloonTipTitle = "Blocking tracking domains.." 
            $balloon.Visible = $true 
            $balloon.ShowBalloonTip(50000)

            Write-host "      BLOCKING - Tracking domains (This may take a while).." -f green
            Start-Sleep -s 3
            Write-Host "        - Backing up your hostsfile.." -f Yellow
            ## Taking backup of current hosts file first
            $hostsfile = "$env:SystemRoot\System32\drivers\etc\hosts"
            $Takebackup = "$env:SystemRoot\System32\drivers\etc\hosts_backup"
            Copy-Item $hostsfile $Takebackup

            Write-Host "        - Getting an updated list of microsoft tracking domains" -f Yellow
            $domain = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt'  -UseBasicParsing
            $domain = $domain.Content | Foreach-object { $_ -replace "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "" } | Foreach-object { $_ -replace " ", "" }
            $domain = $domain.Split("`n") -notlike "#*" -notmatch "spynet2.microsoft.com" -match "\w"

            Write-Host "        - Blocking domains from tracking-list" -f Yellow
            foreach ($domain_entry in $domain) {
            $counter++
                    Write-Progress -Activity 'Adding entries to host file..' -CurrentOperation $domain_entry -PercentComplete (($counter /$domain.count) * 100)
                    Add-Content -Encoding UTF8  $hostsfile ("`t" + "0.0.0.0" + "`t`t" + "$domain_entry") -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 200
            }
            Write-Progress -Completed -Activity "make progress bar dissapear"
            ## flush DNS cache
            Write-host "        - Flushing local DNS cache" -f Yellow
            ipconfig /flushdns | Out-Null; Start-Sleep 2; nbtstat -R | Out-Null; Start-Sleep -s 2;
            Stop-Process -name explorer; Start-Sleep -s 3

        # Blocking Microsoft Tracking IP's in the firewall
            Add-Type -AssemblyName System.Windows.Forms
            $global:balloon = New-Object System.Windows.Forms.NotifyIcon
            $path = (Get-Process -id $pid).Path
            $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
            $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
            $balloon.BalloonTipText = 'Windows Settings'
            $balloon.BalloonTipTitle = "Blocking tracking IP's.." 
            $balloon.Visible = $true 
            $balloon.ShowBalloonTip(50000)

            Write-host "      BLOCKING - Tracking IP's" -f green
            Write-Host "        - Getting updated lists of Microsoft's trackin IP's" -f Yellow
            $blockip = Invoke-WebRequest -Uri https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt  -UseBasicParsing
            $blockip = $blockip.Content | Foreach-object { $_ -replace "0.0.0.0 ", "" } | Out-String
            $blockip = $blockip.Split("`n") -notlike "#*" -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            Clear-Variable -Name counter
            Write-Host "        - Configuring blocking rules in your firewall.." -f Yellow
            foreach ($ip_entry in $blockip) {
            $counter++
            Write-Progress -Activity 'Configuring firewall rules..' -CurrentOperation $ip_entry -PercentComplete (($counter /$blockip.count) * 100)
            netsh advfirewall firewall add rule name="Block Microsoft Tracking IP: $ip_entry" dir=out action=block remoteip=$ip_entry enable=yes | Out-Null}
            Write-Progress -Completed -Activity "make progress bar dissapear"
            Write-Host "        - Firewall configuration complete." -f Yellow
            Start-Sleep -s 3
            
        # Setting DNS to a privacy focused vendor
            $newDNS = ("94.140.14.14", "94.140.15.15") # AD GUARD: https://adguard.com/en/adguard-dns/overview.html
            $ethernetadaptername = (Get-NetAdapter | Where-Object {-not $_.Virtual -and $_.Status -eq 'up'}).Name
            Set-DnsClientServerAddress -InterfaceAlias $ethernetadaptername -ServerAddresses $newDNS; Start-Sleep -s 2
            ipconfig /flushdns; Start-Sleep -s 2
    
    # Other benefitial settings
    
        # Show file extensions
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

        #show hidden files
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
            
        # Change Explorer to "This PC"
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name LaunchTo -Type DWord -Value 1
        
        # Start Menu: Disable Bing Search Results
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type DWord -Value 0

        # Enable Windows Dark Mode
            New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -Value 0 -Type Dword -Force | Out-Null
            New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name SystemUsesLightTheme -Value 0 -Type Dword -Force | Out-Null 

        # Remove login screensaver - preventing missing first character
            If (!(Test-Path HKLM:\Software\Policies\Microsoft\Windows\Personalization)) {
                New-Item -Path HKLM:\Software\Policies\Microsoft\Windows -Name Personalization | Out-Null}
            Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 1