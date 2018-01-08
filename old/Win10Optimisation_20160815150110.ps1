#---------------------------------------------------------------------------------------------
#Windows 10 Optimistion script
#
#Stage 1 : configures various performace settings and installs net 3.5
#stage 2 : removes all appx packages
#stage 3 : further performance settings
#stage 4 : disables un neccesary Services
#stage 5 : disables un neccesary scheduled tasks
#stage 6
#stage 7 : sets the start layout
#---------------------------------------------------------------------------------------------

$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"


function initialchecks
{
    # Validate Windows 10 Enterprise:
    $Edition = Get-WindowsEdition -Online
    If ($Edition.Edition -ne "Enterprise")
        {
        Write-Host "This is not an Enterprise SKU of Windows 10, exiting." -ForegroundColor Red
        Write-Host ""
       Exit
        }
}


function variables
{
    $script:BranchCache = "False"
    $script:Cortana = "False"
    $script:DiagService = "False"
    $script:EAPService = "False"
    $script:EFS = "False"
    $script:FileHistoryService = "False"
    $script:iSCSI = "False"
    $script:MachPass = "True"
    $script:MSSignInService = "True"
    $script:OneDrive = "True"
    $script:PeerCache = "False"
    $script:Search = "True"
    $script:SMB1 = "False"
    $script:SMBPerf = "False"
    $script:Themes = "True"
    $script:Touch = "False"

    $script:StartApps = "False"
    $script:AllStartApps = "True"

    $script:Install_NetFX3 = "True"
    $script:NetFX3_Source = "D:\Sources\SxS"

    $script:RDPEnable = 1
    $script:RDPFirewallOpen = 1
    $script:NLAEnable = 1
    $script:Apps = Get-ProvisionedAppxPackage -Online
}

function prerequisits
{
    # Set up additional registry drives:
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    robocopy \\xendesktop\sharedfiles\scripts-tools C:\scripts-tools
}

function stage1
{
    # Set VM to High Perf scheme:
    Write-Host "Setting VM to High Performance Power Scheme..." -ForegroundColor Green
    Write-Host ""
    POWERCFG -SetActive '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'


    #Install NetFX3
    If ($Install_NetFX3 -eq "True")
    {
        Write-Host "Installing .NET 3.5..." -ForegroundColor Green
        dism /online /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess /Source:$NetFX3_Source /NoRestart
        Write-Host ""
        Write-Host ""
    }

    # Disable "Consumer Features" (aka downloading apps from the internet automatically)
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'CloudContent' | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -PropertyType DWORD -Value '1' | Out-Null
    # Disable the "how to use Windows" contextual popups
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSoftLanding' -PropertyType DWORD -Value '1' | Out-Null 

    Write-Host "Removing (most) built-in Universal Apps..." -ForegroundColor Yellow
    Write-Host ""
    }

function stage2
{
    If ($StartApps -eq "False")
    {

        ForEach ($App in $Apps)
        {
            # News / Sports / Weather
            If ($App.DisplayName -eq "Microsoft.BingFinance")
            {
                Write-Host "Removing Finance App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.BingNews")
            {
                Write-Host "Removing News App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.BingSports")
            {
                Write-Host "Removing Sports App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.BingWeather")
            {
                Write-Host "Removing Weather App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            # Help / "Get" Apps
            If ($App.DisplayName -eq "Microsoft.Getstarted")
            {
                Write-Host "Removing Get Started App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.SkypeApp")
            {
                Write-Host "Removing Get Skype App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.MicrosoftOfficeHub")
            {
                Write-Host "Removing Get Office App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            # Games / XBox apps
            If ($App.DisplayName -eq "Microsoft.XboxApp")
            {
                Write-Host "Removing XBox App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.ZuneMusic")
            {
                Write-Host "Removing Groove Music App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.ZuneVideo")
            {
                Write-Host "Removing Movies & TV App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.MicrosoftSolitaireCollection")
            {
                Write-Host "Removing Microsoft Solitaire Collection App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            # Others
            If ($App.DisplayName -eq "Microsoft.3DBuilder")
            {
                Write-Host "Removing 3D Builder App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.People")
            {
                Write-Host "Removing People App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.Windows.Photos")
            {
                Write-Host "Removing Photos App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.WindowsAlarms")
            {
                Write-Host "Removing Alarms App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            <#
            If ($App.DisplayName -eq "Microsoft.WindowsCalculator")
            {
                Write-Host "Removing Calculator Store App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }
            #>

            If ($App.DisplayName -eq "Microsoft.WindowsCamera")
            {
                Write-Host "Removing Camera App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.WindowsMaps")
            {
                Write-Host "Removing Maps App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.WindowsPhone")
            {
                Write-Host "Removing Phone Companion App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }

            If ($App.DisplayName -eq "Microsoft.WindowsSoundRecorder")
            {
                Write-Host "Removing Voice Recorder App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }
            
            If ($App.DisplayName -eq "Microsoft.Office.Sway")
            {
                Write-Host "Removing Office Sway App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }
            
            If ($App.DisplayName -eq "Microsoft.Messaging")
            {
                Write-Host "Removing Messaging App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }
            
            If ($App.DisplayName -eq "Microsoft.ConnectivityStore")
            {
                Write-Host "Removing Connectivity Store helper App..." -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
            }
        }

        Start-Sleep -Seconds 5
        Write-Host ""
        Write-Host ""

        # Remove (the rest of the) Inbox Universal Apps:
        If ($AllStartApps -eq "False")
        {
            Write-Host "Removing (the rest of the) built-in Universal Apps..." -ForegroundColor Magenta
            Write-Host ""
            ForEach ($App in $Apps)
            {
                If ($App.DisplayName -eq "Microsoft.Office.OneNote")
                {
                    Write-Host "Removing OneNote App..." -ForegroundColor Magenta
                    Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                    Remove-AppxPackage -Package $App.PackageName | Out-Null
                }

                If ($App.DisplayName -eq "Microsoft.windowscommunicationsapps")
                {
                    Write-Host "Removing People, Mail, and Calendar Apps support..." -ForegroundColor Magenta
                    Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                    Remove-AppxPackage -Package $App.PackageName | Out-Null
                }
                
                If ($App.DisplayName -eq "Microsoft.CommsPhone")
                {
                    Write-Host "Removing CommsPhone helper App..." -ForegroundColor Yellow
                    Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                    Remove-AppxPackage -Package $App.PackageName | Out-Null
                }

                If ($App.DisplayName -eq "Microsoft.WindowsStore")
                {
                    Write-Host "Removing Store App..." -ForegroundColor Red
                    Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                    Remove-AppxPackage -Package $App.PackageName | Out-Null
                }
            }
            Start-Sleep -Seconds 5
            Write-Host ""
            Write-Host ""
        }
    }
    \\xendesktop\sharedfiles\scripts\baseimage\win10appremoval.ps1 | Out-Null
}

function stage3
{

    # Disable Cortana:
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Windows Search' | Out-Null
    If ($Cortana -eq "False")
    {
        Write-Host "Disabling Cortana..." -ForegroundColor Yellow
        Write-Host ""
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -PropertyType DWORD -Value '0' | Out-Null
    }


    # Remove OneDrive:
    If ($OneDrive -eq "False")
    {
        # Remove OneDrive (not guaranteed to be permanent - see https://support.office.com/en-US/article/Turn-off-or-uninstall-OneDrive-f32a17ce-3336-40fe-9c38-6efb09f944b0):
        Write-Host "Removing OneDrive..." -ForegroundColor Yellow
        C:\Windows\SysWOW64\OneDriveSetup.exe /uninstall
        Start-Sleep -Seconds 30
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Skydrive' | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Skydrive' -Name 'DisableFileSync' -PropertyType DWORD -Value '1' | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Skydrive' -Name 'DisableLibrariesDefaultSaveToSkyDrive' -PropertyType DWORD -Value '1' | Out-Null 
        Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}' -Recurse
        Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}' -Recurse
        Set-ItemProperty -Path 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value '0'
        Set-ItemProperty -Path 'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value '0' 
    }


    # Set PeerCaching to Disabled (0) or Local Network PCs only (1):
    If ($PeerCache -eq "False")
    {
        Write-Host "Disabling PeerCaching..." -ForegroundColor Yellow
        Write-Host ""
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DODownloadMode' -Value '0'
    }
    Else
    {
        Write-Host "Configuring PeerCaching..." -ForegroundColor Cyan
        Write-Host ""
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DODownloadMode' -Value '1'
    }


}

function stage4
{
    # Disable Services:
    Write-Host "Configuring Services..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Disabling AllJoyn Router Service..." -ForegroundColor Cyan
    Set-Service AJRouter -StartupType Disabled

    Write-Host "Disabling Application Layer Gateway Service..." -ForegroundColor Cyan
    Set-Service ALG -StartupType Disabled

    Write-Host "Disabling Background Intelligent Transfer Service..." -ForegroundColor Cyan
    Set-Service BITS -StartupType Disabled

    Write-Host "Disabling Bitlocker Drive Encryption Service..." -ForegroundColor Cyan
    Set-Service BDESVC -StartupType Disabled

    Write-Host "Disabling Block Level Backup Engine Service..." -ForegroundColor Cyan
    Set-Service wbengine -StartupType Disabled

    Write-Host "Disabling Bluetooth Handsfree Service..." -ForegroundColor Cyan
    Set-Service BthHFSrv -StartupType Disabled

    Write-Host "Disabling Bluetooth Support Service..." -ForegroundColor Cyan
    Set-Service bthserv -StartupType Disabled

    If ($BranchCache -eq "False")
    {
        Write-Host "Disabling BranchCache Service..." -ForegroundColor Yellow
        Set-Service PeerDistSvc -StartupType Disabled
    }

    Write-Host "Disabling Computer Browser Service..." -ForegroundColor Cyan
    Set-Service Browser -StartupType DisableLibrariesDefaultSaveToSkyDrive

    #Disabling this on the Anniversary eddition of Windows 10 causes 10 minute logins!
    #Write-Host "Disabling Device Association Service..." -ForegroundColor Cyan
    #Set-Service DeviceAssociationService -StartupType Disabled
    #device setup disabling was breaking printing
    #Write-Host "Disabling Device Setup Manager Service..." -ForegroundColor Cyan
    #Set-Service DsmSvc -StartupType Disabled

    Write-Host "Disabling Diagnostic Policy Service..." -ForegroundColor Cyan
    Set-Service DPS -StartupType Disabled

    Write-Host "Disabling Diagnostic Service Host Service..." -ForegroundColor Cyan
    Set-Service WdiServiceHost -StartupType Disabled

    Write-Host "Disabling Diagnostic System Host Service..." -ForegroundColor Cyan
    Set-Service WdiSystemHost -StartupType Disabled

    If ($DiagService -eq "False")
    {
        Write-Host "Disabling Diagnostics Tracking Service..." -ForegroundColor Yellow
        Set-Service DiagTrack -StartupType Disabled
    }

    If ($EFS -eq "False")
    {
        Write-Host "Disabling Encrypting File System Service..." -ForegroundColor Yellow
        Set-Service EFS -StartupType Disabled
    }

    If ($EAPService -eq "False")
    {
        Write-Host "Disabling Extensible Authentication Protocol Service..." -ForegroundColor Yellow
        Set-Service Eaphost -StartupType Disabled
    }

    Write-Host "Disabling Fax Service..." -ForegroundColor Cyan
    Set-Service Fax -StartupType Disabled

    Write-Host "Disabling Function Discovery Resource Publication Service..." -ForegroundColor Cyan
    Set-Service FDResPub -StartupType Disabled

    If ($FileHistoryService -eq "False")
    {
        Write-Host "Disabling File History Service..." -ForegroundColor Yellow
        Set-Service fhsvc -StartupType Disabled
    }

    Write-Host "Disabling Geolocation Service..." -ForegroundColor Cyan
    Set-Service lfsvc -StartupType Disabled

    Write-Host "Disabling Home Group Listener Service..." -ForegroundColor Cyan
    Set-Service HomeGroupListener -StartupType Disabled

    Write-Host "Disabling Home Group Provider Service..." -ForegroundColor Cyan
    Set-Service HomeGroupProvider -StartupType Disabled

    Write-Host "Disabling Internet Connection Sharing (ICS) Service..." -ForegroundColor Cyan
    Set-Service SharedAccess -StartupType Disabled

    If ($MSSignInService -eq "False")
    {
        Write-Host "Disabling Microsoft Account Sign-in Assistant Service..." -ForegroundColor Yellow
        Set-Service wlidsvc -StartupType Disabled
    }

    If ($iSCSI -eq "False")
    {
        Write-Host "Disabling Microsoft iSCSI Initiator Service..." -ForegroundColor Yellow
        Set-Service MSiSCSI -StartupType Disabled
    }

    Write-Host "Disabling Microsoft Software Shadow Copy Provider Service..." -ForegroundColor Cyan
    Set-Service swprv -StartupType Disabled

    Write-Host "Disabling Microsoft Storage Spaces SMP Service..." -ForegroundColor Cyan
    Set-Service smphost -StartupType Disabled

    Write-Host "Disabling Offline Files Service..." -ForegroundColor Cyan
    Set-Service CscService -StartupType Disabled

    Write-Host "Disabling Optimize drives Service..." -ForegroundColor Cyan
    Set-Service defragsvc -StartupType Disabled

    Write-Host "Disabling Program Compatibility Assistant Service..." -ForegroundColor Cyan
    Set-Service PcaSvc -StartupType Disabled

    Write-Host "Disabling Quality Windows Audio Video Experience Service..." -ForegroundColor Cyan
    Set-Service QWAVE -StartupType Disabled

    Write-Host "Disabling Retail Demo Service..." -ForegroundColor Cyan
    Set-Service RetailDemo -StartupType Disabled

    Write-Host "Disabling Secure Socket Tunneling Protocol Service..." -ForegroundColor Cyan
    Set-Service SstpSvc -StartupType Disabled

    Write-Host "Disabling Sensor Data Service..." -ForegroundColor Cyan
    Set-Service SensorDataService -StartupType Disabled

    Write-Host "Disabling Sensor Monitoring Service..." -ForegroundColor Cyan
    Set-Service SensrSvc -StartupType Disabled

    Write-Host "Disabling Sensor Service..." -ForegroundColor Cyan
    Set-Service SensorService -StartupType Disabled

    Write-Host "Disabling Shell Hardware Detection Service..." -ForegroundColor Cyan
    Set-Service ShellHWDetection -StartupType Disabled

    Write-Host "Disabling SNMP Trap Service..." -ForegroundColor Cyan
    Set-Service SNMPTRAP -StartupType Disabled

    Write-Host "Disabling Spot Verifier Service..." -ForegroundColor Cyan
    Set-Service svsvc -StartupType Disabled

    Write-Host "Disabling SSDP Discovery Service..." -ForegroundColor Cyan
    Set-Service SSDPSRV -StartupType Disabled

    Write-Host "Disabling Still Image Acquisition Events Service..." -ForegroundColor Cyan
    Set-Service WiaRpc -StartupType Disabled

    Write-Host "Disabling Telephony Service..." -ForegroundColor Cyan
    Set-Service TapiSrv -StartupType Disabled

    If ($Themes -eq "False")
    {
        Write-Host "Disabling Themes Service..." -ForegroundColor Yellow
        Set-Service Themes -StartupType Disabled
    }

    If ($Touch -eq "False")
    {
        Write-Host "Disabling Touch Keyboard and Handwriting Panel Service..." -ForegroundColor Yellow
        Set-Service TabletInputService -StartupType Disabled
    }

    Write-Host "Disabling UPnP Device Host Service..." -ForegroundColor Cyan
    Set-Service upnphost -StartupType Disabled

    Write-Host "Disabling Volume Shadow Copy Service..." -ForegroundColor Cyan
    Set-Service VSS -StartupType Disabled

    Write-Host "Disabling Windows Color System Service..." -ForegroundColor Cyan
    Set-Service WcsPlugInService -StartupType Disabled

    Write-Host "Disabling Windows Connect Now - Config Registrar Service..." -ForegroundColor Cyan
    Set-Service wcncsvc -StartupType Disabled

    Write-Host "Disabling Windows Error Reporting Service..." -ForegroundColor Cyan
    Set-Service WerSvc -StartupType Disabled

    Write-Host "Disabling Windows Image Acquisition (WIA) Service..." -ForegroundColor Cyan
    Set-Service stisvc -StartupType Disabled

    Write-Host "Disabling Windows Media Player Network Sharing Service..." -ForegroundColor Cyan
    Set-Service WMPNetworkSvc -StartupType Disabled

    Write-Host "Disabling Windows Mobile Hotspot Service..." -ForegroundColor Cyan
    Set-Service icssvc -StartupType Disabled

    If ($Search -eq "False")
    {
        Write-Host "Disabling Windows Search Service..." -ForegroundColor Yellow
        Set-Service WSearch -StartupType Disabled
    }

    Write-Host "Disabling WLAN AutoConfig Service..." -ForegroundColor Cyan
    Set-Service WlanSvc -StartupType Disabled

    Write-Host "Disabling WWAN AutoConfig Service..." -ForegroundColor Cyan
    Set-Service WwanSvc -StartupType Disabled

    Write-Host "Disabling Xbox Live Auth Manager Service..." -ForegroundColor Cyan
    Set-Service XblAuthManager -StartupType Disabled

    Write-Host "Disabling Xbox Live Game Save Service..." -ForegroundColor Cyan
    Set-Service XblGameSave -StartupType Disabled

    Write-Host "Disabling Xbox Live Networking Service Service..." -ForegroundColor Cyan
    Set-Service XboxNetApiSvc -StartupType Disabled
    Write-Host ""


    # Reconfigure / Change Services:
    Write-Host "Configuring Network List Service to start Automatic..." -ForegroundColor Green
    Write-Host ""
    Set-Service netprofm -StartupType Automatic
    Write-Host ""

    Write-Host "Configuring Windows Update Service to run in standalone svchost..." -ForegroundColor Cyan
    Write-Host ""
    sc.exe config wuauserv type= own
    Write-Host ""
}

function stage5
{
    # Disable Scheduled Tasks:
    Write-Host "Disabling Scheduled Tasks..." -ForegroundColor Cyan
    Write-Host ""
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Bluetooth\UninstallDeviceTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Diagnosis\Scheduled" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maintenance\WinSAT" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maps\MapsToastTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maps\MapsUpdateTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Ras\MobilityManager" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Registry\RegIdleBackup" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\FamilySafetyMonitor" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\FamilySafetyRefresh" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\SystemRestore\SR" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\UPnP\UPnPHostConfig" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\WDI\ResolutionHost" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\WOF\WIM-Hash-Management" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\WOF\WIM-Hash-Validation" | Out-Null
}

function stage6
{
    # Disable Hard Disk Timeouts:
    Write-Host "Disabling Hard Disk Timeouts..." -ForegroundColor Yellow
    Write-Host ""
    POWERCFG /SETACVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
    POWERCFG /SETDCVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0


    # Disable Hibernate
    Write-Host "Disabling Hibernate..." -ForegroundColor Green
    Write-Host ""
    POWERCFG -h off


    # Disable Large Send Offload
    Write-Host "Disabling TCP Large Send Offload..." -ForegroundColor Green
    Write-Host ""
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name 'DisableTaskOffload' -PropertyType DWORD -Value '1' | Out-Null


    # Disable System Restore
    Write-Host "Disabling System Restore..." -ForegroundColor Green
    Write-Host ""
    Disable-ComputerRestore -Drive "C:\"


    # Disable NTFS Last Access Timestamps
    Write-Host "Disabling NTFS Last Access Timestamps..." -ForegroundColor Yellow
    Write-Host ""
    FSUTIL behavior set disablelastaccess 1 | Out-Null

    If ($MachPass -eq "False")
    {
        # Disable Machine Account Password Changes
        Write-Host "Disabling Machine Account Password Changes..." -ForegroundColor Yellow
        Write-Host ""
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DisablePasswordChange' -Value '1'
    }


    # Disable Memory Dumps
    Write-Host "Disabling Memory Dump Creation..." -ForegroundColor Green
    Write-Host ""
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -Value '1'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'LogEvent' -Value '0'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'SendAlert' -Value '0'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'AutoReboot' -Value '1'


    # Increase Service Startup Timeout:
    Write-Host "Increasing Service Startup Timeout To 180 Seconds..." -ForegroundColor Yellow
    Write-Host ""
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'ServicesPipeTimeout' -Value '180000'


    # Increase Disk I/O Timeout to 200 Seconds:
    Write-Host "Increasing Disk I/O Timeout to 200 Seconds..." -ForegroundColor Green
    Write-Host ""
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Disk' -Name 'TimeOutValue' -Value '200'


    # Disable IE First Run Wizard:
    Write-Host "Disabling IE First Run Wizard..." -ForegroundColor Green
    Write-Host ""
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft' -Name 'Internet Explorer' | Out-Null
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -Name 'Main' | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -PropertyType DWORD -Value '1' | Out-Null


    # Disable New Network Dialog:
    Write-Host "Disabling New Network Dialog..." -ForegroundColor Green
    Write-Host ""
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Network' -Name 'NewNetworkWindowOff' | Out-Null


    If ($SMB1 -eq "False")
    {
        # Disable SMB1:
        Write-Host "Disabling SMB1 Support..." -ForegroundColor Yellow
        dism /online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart
        Write-Host ""
        Write-Host ""
    }


    If ($SMBPerf -eq "True")
    {
        # SMB Modifications for performance:
        Write-Host "Changing SMB Parameters..."
        Write-Host ""
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DisableBandwidthThrottling' -PropertyType DWORD -Value '1' | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DisableLargeMtu' -PropertyType DWORD -Value '0' | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'FileInfoCacheEntriesMax' -PropertyType DWORD -Value '8000' | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DirectoryCacheEntriesMax' -PropertyType DWORD -Value '1000' | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'FileNotFoundcacheEntriesMax' -PropertyType DWORD -Value '1' | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'MaxCmds' -PropertyType DWORD -Value '8000' | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableWsd' -PropertyType DWORD -Value '0' | Out-Null
    }

    $delayRegLocation = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    write-host "checking existing registry paths to the Startup Delay key `n" -foregroundcolor cyan

    #initialize KeyExists
    $KeyExists = "none"
    $DelayLogonPath = test-path "$delayRegLocation\Serialize"

    #if the key exists, this checks its value and if value is correct will tell user and will change KeyExists to "exists"
    if ($DelayLogonPath)
        {
            $keycheck = Get-ItemProperty -Path "$delayRegLocation\Serialize" -name "StartupDelayInMSec" -ErrorAction SilentlyContinue;$keyvalue=$keycheck.StartupDelayInMSec
                if ($keyvalue -eq "00000000")
                {
                    $KeyExists = "exists"
                }
        }

    if(($DelayLogonPath) -and !($keyvalue -eq "00000000"))
        {
            write-host "StartupDelayInMSec key value `n" -ForegroundColor Yellow
            set-itemproperty -path "$delayRegLocation\Serialize" -name "StartupDelayInMSec"  -value "00000000" | out-null
            
        }
    elseif (!($DelayLogonPath))#creates path if this does not exist and key
        {
            write-host "creating registry path the StartupDelayInMSec Key `n" -foregroundcolor yellow
            if (!(test-path "$delayRegLocation"))
            {
                new-item -path "$delayRegLocation" | out-null
            }
            if (!(test-path "$delayRegLocation\Serialize"))
            {
                new-item -path "$delayRegLocation\Serialize" | out-null
            }
            write-host "Creating StartupDelayInMSec Properties `n" -ForegroundColor Yellow
            new-itemproperty -path "$delayRegLocation\Serialize" -name "StartupDelayInMSec" -PropertyType "DWORD" -value "00000000" | out-null
        }

    #final checking that Start Layout key exists and has corect value
    $keyverification = Get-ItemProperty -Path "$delayRegLocation\Serialize" -name "StartupDelayInMSec" -ErrorAction SilentlyContinue
    $keyverificationvalue=$keyverification.StartupDelayInMSec
    write-host "checking that the StartupDelayInMSec key exists `n" -foregroundcolor cyan
    if ($keyverificationvalue -eq "00000000")
        {
            write-host "StartupDelayInMSec Key exists `n" -ForegroundColor Green
        }
    else
        {
            write-host " StartupDelayInMSec Key not created! `nplease manually create the key in $delayRegLocation\Serialize" -foregroundcolor red
        }


    # Remove Previous Versions:
    Write-Host "Removing Previous Versions Capability..." -ForegroundColor Yellow
    Write-Host ""
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\\Microsoft\Windows\CurrentVersion\Explorer' -Name 'NoPreviousVersionsPage' -Value '1'


    # Change Explorer Default View:
    Write-Host "Configuring Windows Explorer..." -ForegroundColor Green
    Write-Host ""
    New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -PropertyType DWORD -Value '1' | Out-Null


    # Configure Search Options:
    Write-Host "Configuring Search Options..." -ForegroundColor Green
    Write-Host ""
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -PropertyType DWORD -Value '0' | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -PropertyType DWORD -Value '0' | Out-Null
    New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'SearchboxTaskbarMode' -PropertyType DWORD -Value '1' | Out-Null


    # Use Solid Background Color:
    Write-Host "Configuring Winlogon..." -ForegroundColor Green
    Write-Host ""
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLogonBackgroundImage' -Value '1'


    # DisableTransparency:
    Write-Host "Removing Transparency Effects..." -ForegroundColor Green
    Write-Host ""
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'EnableTransparency' -Value '0'
}

function officechecker
{
    if ((Get-WmiObject -Class Win32_ComputerSystem).SystemType -match '(x64)')
        {
            $list = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName
        }
    else
        {
            $list = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName
        }
    if ($list -match "Microsoft Office Professional Plus 2016")
        {
            stage7office2016
        }

    elseif ($list -match "Microsoft Office Professional Plus 2013")
        {
            stage7office2013
        }

    else
    {
        write-host "Start layout not set, most likely cause is that Office version does not match" -ForegroundColor red
    }

}

function stage7office2016
{
    $RegLocation = "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows"
    write-host "checking existing registry paths to the Start Layout `n" -foregroundcolor cyan

    #initialize KeyExists
    $KeyExists = "none"
    $ExplorerPath = test-path "$RegLocation\Explorer"

    #if the key exists, this checks its value and if value is correct will tell user and will change KeyExists to "exists"
    if ($ExplorerPath)
        {
            $keycheck = Get-ItemProperty -Path "$RegLocation\Explorer" -name "StartLayoutFile" -ErrorAction SilentlyContinue;$keyvalue=$keycheck.StartLayoutFile
                if ($keyvalue -eq "C:\scripts-tools\start.xml")
                {
                    $KeyExists = "exists"
                }
        }

    if(($ExplorerPath) -and !($keyvalue -eq "C:\scripts-tools\start.xml"))
        {
            write-host "setting Start Layout key value `n" -ForegroundColor Yellow
            set-itemproperty -path "$RegLocation\Explorer" -name "StartLayoutFile"  -value "C:\scripts-tools\start.xml" | out-null

        }
    elseif (!($ExplorerPath))#creates path if this does not exist and key
        {
            write-host "creating registry path the Start Layout Key `n" -foregroundcolor yellow
            if (!(test-path "$RegLocation"))
            {
                new-item -path "$RegLocation" | out-null
            }
            if (!(test-path "$RegLocation\Explorer"))
            {
                new-item -path "$RegLocation\Explorer" | out-null
            }
            write-host "Creating Start Layout Key Properties `n" -ForegroundColor Yellow
            new-itemproperty -path "$RegLocation\Explorer" -name "StartLayoutFile" -PropertyType "String" -value "C:\scripts-tools\start.xml" | out-null
        }

    #final checking that Start Layout key exists and has corect value
    $keyverification = Get-ItemProperty -Path "$RegLocation\Explorer" -name "StartLayoutFile" -ErrorAction SilentlyContinue
    $keyverificationvalue=$keyverification.StartLayoutFile
    write-host "checking that the Start Layout key exists `n" -foregroundcolor cyan
    if ($keyverificationvalue -eq "C:\scripts-tools\start.xml")
        {
            write-host "Start Layout Key exists `n" -ForegroundColor Green
        }
    else
        {
            write-host "Start Layout Key not created! `nplease manually create the key in $Reglocation\Explorer" -foregroundcolor red
        }

    #if the key exists, this checks its value and if value is correct will tell user and will change KeyExists to "exists"
    if ($ExplorerPath)
        {
            $keycheck = Get-ItemProperty -Path "$RegLocation\Explorer" -name "LockedStartLayout" -ErrorAction SilentlyContinue;$keyvalue=$keycheck.LockedStartLayout
                if ($keyvalue -eq "0x00000001")
                {
                    $KeyExists = "exists"
                }
        }

    if(($ExplorerPath) -and !($keyvalue -eq "0x00000001"))
        {
            write-host "setting locked start layout key value `n" -ForegroundColor Yellow
            set-itemproperty -path "$RegLocation\Explorer" -name "LockedStartLayout"  -value "0x00000001" | out-null
            
        }
    elseif (!($ExplorerPath))#creates path if this does not exist and key
        {
            write-host "creating registry path the Locked Start Layout Key `n" -foregroundcolor yellow
            if (!(test-path "$RegLocation"))
            {
                new-item -path "$RegLocation" | out-null
            }
            if (!(test-path "$RegLocation\Explorer"))
            {
                new-item -path "$RegLocation\Explorer" | out-null
            }
            write-host "Creating Locked Start Layout Key Properties `n" -ForegroundColor Yellow
            new-itemproperty -path "$RegLocation\Explorer" -name "LockedStartLayout" -PropertyType "DWORD" -value "0x00000001" | out-null
        }

    #final checking that Start Layout key exists and has corect value
    $keyverification = Get-ItemProperty -Path "$RegLocation\Explorer" -name "LockedStartLayout" -ErrorAction SilentlyContinue
    $keyverificationvalue=$keyverification.LockedStartLayout
    write-host "checking that the Locked Start Layout key exists `n" -foregroundcolor cyan
    if ($keyverificationvalue -eq "0x00000001")
        {
            write-host "Locked Start Layout Key exists `n" -ForegroundColor Green
        }
    else
        {
            write-host " LockedStart Layout Key not created! `nplease manually create the key in $Reglocation\Explorer" -foregroundcolor red
        }

}

function stage7office2013
{
    $RegLocation = "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows"
    write-host "checking existing registry paths to the Start Layout `n" -foregroundcolor cyan

    #initialize KeyExists
    $KeyExists = "none"
    $ExplorerPath = test-path "$RegLocation\Explorer"

    #if the key exists, this checks its value and if value is correct will tell user and will change KeyExists to "exists"
    if ($ExplorerPath)
        {
            $keycheck = Get-ItemProperty -Path "$RegLocation\Explorer" -name "StartLayoutFile" -ErrorAction SilentlyContinue;$keyvalue=$keycheck.StartLayoutFile
                if ($keyvalue -eq "C:\scripts-tools\start2013.xml")
                {
                    $KeyExists = "exists"
                }
        }

    if(($ExplorerPath) -and !($keyvalue -eq "C:\scripts-tools\start2013.xml"))
        {
            write-host "setting Start Layout key value `n" -ForegroundColor Yellow
            set-itemproperty -path "$RegLocation\Explorer" -name "StartLayoutFile"  -value "C:\scripts-tools\start2013.xml" | out-null

        }
    elseif (!($ExplorerPath))#creates path if this does not exist and key
        {
            write-host "creating registry path the Start Layout Key `n" -foregroundcolor yellow
            if (!(test-path "$RegLocation"))
            {
                new-item -path "$RegLocation" | out-null
            }
            if (!(test-path "$RegLocation\Explorer"))
            {
                new-item -path "$RegLocation\Explorer" | out-null
            }
            write-host "Creating Start Layout Key Properties `n" -ForegroundColor Yellow
            new-itemproperty -path "$RegLocation\Explorer" -name "StartLayoutFile" -PropertyType "String" -value "C:\scripts-tools\start2013.xml" | out-null
        }

    #final checking that Start Layout key exists and has corect value
    $keyverification = Get-ItemProperty -Path "$RegLocation\Explorer" -name "StartLayoutFile" -ErrorAction SilentlyContinue
    $keyverificationvalue=$keyverification.StartLayoutFile
    write-host "checking that the Start Layout key exists `n" -foregroundcolor cyan
    if ($keyverificationvalue -eq "C:\scripts-tools\start2013.xml")
        {
            write-host "Start Layout Key exists `n" -ForegroundColor Green
        }
    else
        {
            write-host "Start Layout Key not created! `nplease manually create the key in $Reglocation\Explorer" -foregroundcolor red
        }

    #if the key exists, this checks its value and if value is correct will tell user and will change KeyExists to "exists"
    if ($ExplorerPath)
        {
            $keycheck = Get-ItemProperty -Path "$RegLocation\Explorer" -name "LockedStartLayout" -ErrorAction SilentlyContinue;$keyvalue=$keycheck.LockedStartLayout
                if ($keyvalue -eq "0x00000001")
                {
                    $KeyExists = "exists"
                }
        }

    if(($ExplorerPath) -and !($keyvalue -eq "0x00000001"))
        {
            write-host "setting locked start layout key value `n" -ForegroundColor Yellow
            set-itemproperty -path "$RegLocation\Explorer" -name "LockedStartLayout"  -value "0x00000001" | out-null
            
        }
    elseif (!($ExplorerPath))#creates path if this does not exist and key
        {
            write-host "creating registry path the Locked Start Layout Key `n" -foregroundcolor yellow
            if (!(test-path "$RegLocation"))
            {
                new-item -path "$RegLocation" | out-null
            }
            if (!(test-path "$RegLocation\Explorer"))
            {
                new-item -path "$RegLocation\Explorer" | out-null
            }
            write-host "Creating Locked Start Layout Key Properties `n" -ForegroundColor Yellow
            new-itemproperty -path "$RegLocation\Explorer" -name "LockedStartLayout" -PropertyType "DWORD" -value "0x00000001" | out-null
        }

    #final checking that Start Layout key exists and has corect value
    $keyverification = Get-ItemProperty -Path "$RegLocation\Explorer" -name "LockedStartLayout" -ErrorAction SilentlyContinue
    $keyverificationvalue=$keyverification.LockedStartLayout
    write-host "checking that the Locked Start Layout key exists `n" -foregroundcolor cyan
    if ($keyverificationvalue -eq "0x00000001")
        {
            write-host "Locked Start Layout Key exists `n" -ForegroundColor Green
        }
    else
        {
            write-host " LockedStart Layout Key not created! `nplease manually create the key in $Reglocation\Explorer" -foregroundcolor red
        }  
}

function endscript
{
        If ($NoWarn -eq $False)
        {
            Write-Host "This script has completed." -ForegroundColor Green
            Write-Host ""
            Write-Host "Please review output in your console for any indications of failures, and resolve as necessary." -ForegroundColor Yellow
            Write-Host ""
        }
}

function run-script
{
    Write-Host "Windows 10 Optimisation script!

      "

    initialchecks
    variables
    prerequisits
    stage1
    stage2
    stage3
    stage4
    stage5
    stage6
    officechecker

}

run-script