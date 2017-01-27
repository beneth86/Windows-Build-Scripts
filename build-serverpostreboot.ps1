# Set up and start logging
function Start-Log {
    param(
        [string]$sessName
    )
    
    try {Stop-Transcript} catch {}

    $filename = (Get-Date).ToString('MMddyyyyhhmmss');

    if ([System.String]::IsNullOrEmpty($sessName)){
        Start-Transcript -Path "$PSScriptRoot\$filename.txt" -NoClobber
    }
    else {
        Start-Transcript -Path "$PSScriptRoot\$sessName$filename.txt" -NoClobber
    }
}

Set-Alias Stop-Log Stop-Transcript

Start-Log

# Change to DeploymentTools Directory
cd c:\Deploy

# Remove Scheduled Task
Write-Host "Removing post-reboot job..."
Get-ScheduledTask -TaskName BuildTask | Unregister-ScheduledTask -Confirm:$false

# Disable Microsoft Monitoring Agent Service
Write-Host "Checking Microsoft Monitoring Agent Status..."
$status = Get-WMIObject Win32_Service -filter "name='HealthService'"
if ($status.StartMode -eq "Disabled")
{
    Write-Output ("Microsoft Monitoring Agent is already disabled...")
}
else
{
    Write-Output ("Microsoft Monitoring Agent is enabled. Disabling...")
    Get-Service HealthService | Stop-Service -PassThru | Set-Service -StartupType disabled
}

# Clear IE Proxy Settings
$reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
if ($reg)
{
    Remove-ItemProperty -Path $reg -Name ProxyServer
    Set-ItemProperty -Path $reg -Name ProxyEnable -Value 0
}

# If we'd prefer to just disable the proxy
#$reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
#if ($reg)
#{
#    Set-ItemProperty -Path $reg -Name ProxyEnable -Value 0
#}

# Run Symantec Client Reset Tool as Symantec Endpoint Protection is pre-installed on templates
Write-Host "Running Symantec Reset..."
D:\Deploy\ClientSideClonePrepTool.exe

# Run DISM
Write-Host "Running DISM..."
c:\Windows\SysNative\dism.exe /online /cleanup-image /SPSuperseded
c:\Windows\SysNative\dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase


# Remove staged files
# Build menu for removing staged files
$title = "Remove staged files?"
$message = "Are you ready to remove staged build files?"

$Yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
    "Delete staged files"

$No = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
    "DO NOT delete staged files"

$options = [System.Management.Automation.Host.ChoiceDescription[]]($Yes, $No)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
{
    0 {
        # Delete the files
        Write-Host "Deleting DeploymentTools Folder..." -ForegroundColor "Yellow"
        Remove-Item C:\Deploy -Recurse -Force
    }
    1 {
        # Don't delete the files
        Write-Host "Not automatically removing staged files." -ForegroundColor Yellow
        Write-Host "Remember to Delete Staged Folder. Thank you!!" -ForegroundColor Yellow
    }
}

Stop-Log