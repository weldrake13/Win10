#---------------------------------------------------------------------------------------------
#Windows 10 Optimistion script
#
#Stage 1 : configures various performace settings and installs net 3.5
#stage 2 : removes relevent appx packages
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
    # check Win 10 Enterprise:
    $Edition = Get-WindowsEdition -Online
    If ($Edition.Edition -ne "Enterprise")
        {
        Write-Host "Please run on the enterprise edition of windows 10" -ForegroundColor Red
        Write-Host ""
       #Exit
        }
    elseif ($Edition.Edition -ne "Professional")
        {
            ##
        }
}


function variables
{
    $script:Cortana = "False"
    $script:EAPService = "False"
    $script:FileHistoryService = "False"
    $script:MachPass = "True"
    $script:MSSignInService = "True"
    $script:OneDrive = "True"
    $script:PeerCache = "False"
    $script:Search = "True"
    $script:SMB1 = "False"
    $script:SMBPerf = "False"
    $script:Themes = "True"
    $script:Touch = "False"
    $script:WinBuild = [System.Environment]::OSVersion.Version | select -expand Build

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
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    #robocopy \\192.168.100.60\v\resources\scripts-tools c:\scripts-tools

    
}

function stage1
{
    # Set High Performance 
    Write-Host "Setting VM to High Performance Power Scheme..." -ForegroundColor Green
    Write-Host ""
    POWERCFG -SetActive '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'



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
    $csvapps = Import-Csv C:\scripts-tools\w10opt\Win10Apps.csv
    if ($WinBuild -eq 10586)
    {
        write-host "Windows 10 Non-Anniversary edition installed"
        foreach ($app in $csvapps)
        {
            $uninstall = $app.AppName
            Get-AppxPackage -allusers *$uninnstall* | Remove-AppxPackage -ErrorAction SilentlyContinue |Out-Null
        }
    }

    elseif ($WinBuild -eq 14393) 
    {
        write-host "Windows 10 Anniversary installed"
        foreach ($app in $csvapps)
        {
            $uninstall = $app.AppName
            Get-AppxPackage -allusers *$uninnstall* | Remove-AppxPackage -ErrorAction SilentlyContinue |Out-Null
        }
    }

    else
    {
        write-host "unable to detect Windows Build, running default apps."
        foreach ($app in $csvapps)
        {
            $uninstall = $app.AppName
            Get-AppxPackage -allusers *$uninnstall* | Remove-AppxPackage -ErrorAction SilentlyContinue |Out-Null
        }
    }

    

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

    $csvservices = Import-Csv C:\scripts-tools\w10opt\services.csv
    foreach ($service in $csvservices)
    {
        $servicename = $service.ServiceName
        $servicefriendlyname = $service.ServiceFriendlyName

        write-host "disabling $servicefriendlyname service" -ForegroundColor cyan
        set-service $servicename -StartupType Disabled
    }


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