## Need to be fixed list:
#   Empty..


# Install chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force;
    New-Item -Type File -Force $PROFILE
    (New-Object System.Net.WebClient).DownloadFile("https://chocolatey.org/install.ps1","$env:TMP/choco-install.ps1")
    # Executing installation file.
    cd $env:TMP; .\choco-install.ps1
    write-host "choco installed."
    
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
        $balloon.BalloonTipTitle = "Unpinning apps.." 
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

        # General
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

            # Disable Let Windows track app launches to improve Stat and search results
            If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
            Set-ItemProperty -Path  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs"  -Value 0    

            # Disable Show me suggested content in the Settings app
            Write-host "        - Disabling personalized content suggestions." -f Yellow
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
            Start-Sleep -s 2
        
        # Speech
            # Disable Online Speech Recognition
            Write-host "        - Disabling Online Speech Recognition." -f yellow
            If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
                New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 0
            Start-Sleep -s 2

        # Inking & Typing Personalization
            # Use typing history patterns to create personal dictionary
            If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
                New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null}
            Set-ItemProperty -Path  "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection"  -Value 1
            Set-ItemProperty -Path  "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection"  -Value 1
            Start-Sleep -s 2
        
        # Diagnostics & feedback
                
            # Diagnostic data collection
            If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection")) {
                New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null}
            Set-ItemProperty -Path  "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"  -Value 0
            Start-Sleep -s 2
            
            
            # Tailored expirence
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy")) {   
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Force | Out-Null}
                Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled"  -Value 0
                Start-Sleep -s 2
                
        # Activity history
            
            # Disable "Store my activity on this device"
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {   
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null}
            Set-ItemProperty -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities"  -Value 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
            Start-Sleep -s 2

                    
            
        #Other
            
            # Hiding personal information from lockscreen
                If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System")) {
                    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Force | Out-Null}
                Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayLockedUserID" -Type DWord -Value 0
                Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayLastUsername" -Type DWord -Value 0
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
            
        
    # Other beneficial settings
    
        # Show file extensions
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

        #show hidden files
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
            
        # Change Explorer to "This PC"
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
        
        # Start Menu: Disable Bing Search Results
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0

        # Enable Windows Dark Mode
            New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type Dword -Force | Out-Null
            New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Type Dword -Force | Out-Null 

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
        
        # Removing printers
            If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
                New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null}
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
            Get-Printer | Where-Object Name -Like * | Remove-Printer -ErrorAction SilentlyContinue
        
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

        # Create powershell profile
            New-Item -Type File -Force $PROFILE

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