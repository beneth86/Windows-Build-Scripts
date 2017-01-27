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

# Set up scheduled task to relaunch next step of config scripts after rebooting
Write-Host "Creating post-reboot job..."
$action = '-NoExit -Command "&''c:\deploy\build-serverpostreboot.ps1''"'
$pstart =  "C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell.exe"
$act = New-ScheduledTaskAction -Execute $pstart -Argument $action
$trig = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName BuildTask -Action $act -Trigger $trig -RunLevel Highest

# Change to Deploy Directory
cd c:\Deploy

# Disable Windows Firewall
Write-Host "Checking Windows Firewall Status..."
$status = Get-WMIObject Win32_Service -filter "name='MpsSvc'"
if ($status.StartMode -eq "Disabled")
{
    Write-Output ("Firewall is already disabled...")
}
else
{
    Write-Output ("Firewall is enabled. Disabling...")
    Get-Service MpsSvc | Stop-Service -PassThru | Set-Service -StartupType disabled
}

# Disable NetBios and IPv6 for all adapters
Write-Host "Disabling NetBIOS and IPv6 for all adapters..."
Disable-NetAdapterBinding -Name * -ComponentID ms_tcpip6
$adapters = (gwmi win32_networkadapterconfiguration)
Foreach ($adapter in $adapters){
    Write-Host $adapter
    $adapter.settcpipnetbios(2) | Out-Null
}

# Build menu for initializing any extra disks
$title = "Initialize Extra Disks?"
$message = "Do you need to initialize any extra disks?"

$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Initialize any extra system disks."

$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Skip extra disk initialization."

$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
{
    0 {
        Write-Host "Initializing extra disks..."

        # Initialize any extra disks (Virtual)
        Get-Disk | Where FriendlyName -eq "VMware Virtual disk SCSI Disk Device" | Where PartitionStyle -eq 'RAW' | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data" -Confirm:$false

        # Initialize any extra disks (Physical)
        Get-Disk | Where FriendlyName -ne "VMware Virtual disk SCSI Disk Device" | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data" -Confirm:$false
    }
    1 {
        "You selected No, moving along."
    }
}

# Set Virtual Memory Settings
Write-Host "Setting Virtual Memory Settings..."
Import-Module c:\Deploy\AdjustVirtualMemoryPagingFileSize.psm1
Set-OSCVirtualMemory -InitialSize 2048 -MaximumSize 4096 -DriveLetter "C:"

# Change system description
Write-Host "System Description Guidelines Here: "
$newdesc = Read-Host "Enter New System Description"
$desc = Get-WmiObject -class Win32_OperatingSystem
$desc.Description = $newdesc
$desc.Put()

# Set Boot Countdown Timeout
Write-Host "Setting Boot Timeout..."
bcdedit /timeout 5

# Build menu for changing the IP
$title = "Change the IP?"
$message = "Do you want to change the IP of the computer?"

$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
    "Change the IP."

$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
    "Retains current IP."

$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
{
    0 {
        # Prompt for network settings
        $ip = Read-Host "Enter IP Address"
        $mask = Read-Host "Enter Subnet Mask in CIDR Notation without slash (Example: 24)"
        $gateway = Read-Host "Enter Gateway"
        $dns1 = Read-Host "Enter Primary DNS Server"
        $dns2 = Read-Host "Enter Secondary DNS Server"

        # Remove any current IPv4 config
        $adapter = Get-NetAdapter | ? {$_.Status -eq "up"}
        If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
            $adapter | Remove-NetIPAddress -AddressFamily IPv4 -Confirm:$false
        }
        
        If (($adapter | Get-NetIPConfiguration).IPv4DefaultGateway) {
            $adapter | Remove-NetRoute -AddressFamily IPv4 -Confirm:$false
        }
        
        # Configure new network settings
        $adapter | New-NetIPAddress -AddressFamily IPv4 -IPAddress $IP -PrefixLength $mask -DefaultGateway $Gateway
        $adapter | Set-DnsClientServerAddress -ServerAddresses $dns1,$dns2
    }
    1 {
        "You selected No, moving along."
    }
}

# Build menu for domain join
$title = "Join a Domain"
$message = "Select the domain you'd like to join."

$Domain1 = New-Object System.Management.Automation.Host.ChoiceDescription "&Domain1", `
    "Join the Domain1 domain"

$Domain2 = New-Object System.Management.Automation.Host.ChoiceDescription "&Domain2", `
    "Join the Domain2 domain"

$Domain3 = New-Object System.Management.Automation.Host.ChoiceDescription "&Domain3", `
    "Join the Domain3 domain"


$options = [System.Management.Automation.Host.ChoiceDescription[]]($Domain1, $Domain2, $Domain3)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
{
    0 {
        # Join the Domain1 domain
        $cred = Get-Credential
        Add-Computer -DomainName Domain1.com -Credential $cred
    }
    1 {
        # Join the Domain2 domain
        $cred = Get-Credential
        Add-Computer -DomainName Domain2.local -Credential $cred
    }
    2 {
        # Join the Domain3 domain
        $cred = Get-Credential
        Add-Computer -DomainName Domain3.local -Credential $cred
    }
}

# Add DNS suffix/registration checkbox
Get-NetAdapter | Set-DnsClient -ConnectionSpecificSuffix $env:USERDNSDOMAIN -RegisterThisConnectionsAddress $true

# Add correct group to local administrators
function AddADUserToLocalAdminGrp
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$domain,
		
		[Parameter(Mandatory = $true)]
		[string[]]$groups
		
	)
	begin { Write-Verbose -Message "Attempting to add AD users to the Local Administrators Group..." }
	process
	{
        foreach ($group in $groups) {
            $DomainGroup = [ADSI]"WinNT://$domain/$group,group"
            $LocalGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
            $LocalGroup.Add($DomainGroup.Path)
        }
	}
	end { }
}

switch -Wildcard ($env:USERDOMAIN)
{
	"*Domain1*" { AddADUserToLocalAdminGrp -domain "Domain1" -groups "Group1", "Group2", "Group3"}
	"*Domain2*" { AddADUserToLocalAdminGrp -domain "Domain2" -groups "Group1", "Group2", "Group3"}
	"*Domain3*" { AddADUserToLocalAdminGrp -domain "Domain3" -groups "Group1", "Group2", "Group3" }
	Default { "Unable to determine the system domain - No action taken..." }
}

# Build menu for "Adjust for Best Performance" setting to "Programs" for SQL Builds
$title = "SQL Build?"
$message = "Do you want to Change 'Adjust for Best Performance' setting to 'Programs' for SQL Build?"

$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
    "Changes 'Adjust for Best Performance' setting to 'Programs' for SQL Build."

$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
    "Retains default template setting."

$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
{
    0 {
        Write-Host "Setting 'Adjust for Best Performance' setting to 'Programs'..."
        Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\PriorityControl -Name Win32PrioritySeparation -Value 0x00000026
        Write-Host "Setting SQL SubSystems Value..."
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\SubSystems" -Name Windows -Value "%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,4096 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16"
    }
    1 {
        "You selected No, moving along."
    }
}

# Install Telnet Client if not currently installed
$check = get-windowsfeature -name Telnet-Client
if ($check.Installed -ne "True") {
    #Install/Enable Telnet Client
    Write-Host "Installing Telnet Client"
    add-windowsfeature Telnet-Client -includeManagementTools | Out-Null
}

# Build menu for installing IIS
$title = "Install IIS?"
$message = "Do you want to install IIS?"

$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
    "Installs IIS and adds MIME entry."

$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
    "Skips IIS install."

$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
{
    0 {
        # Install IIS and Management Console
        import-module servermanager
        add-windowsfeature Web-Server -includeManagementTools

        # Add MIME type .fhs "text/plain"
        & $Env:WinDir\system32\inetsrv\appcmd.exe set config /section:staticContent /+"[fileExtension='.fhs',mimeType='text/plain']"
    }
    1 {
        "You selected No, moving along."
    }
}

# Build menu for installing extra server roles
$title = "Extra Modules?"
$message = "Do you want to install extra (physical build) server roles?"

$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
    "Installs additional server roles."

$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
    "Skips installing server roles."

$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
{
    0 {
        # Install extra server modules
        Write-Host "Adding Application Server Role..."
        Add-WindowsFeature Application-Server -includeManagementTools
        Write-Host "Adding Incoming Transactions Role..."
        Add-WindowsFeature AS-Incoming-Trans -includeManagementTools
        Write-Host "Adding Outgoing Transactions Role..."
        Add-WindowsFeature AS-Outgoing-Trans -includeManagementTools
        Write-Host "Adding Webserver Support Role..."
        Add-WindowsFeature AS-Web-Support -includeManagementTools
        Write-Host "Adding Multipath-IO Role..."
        Add-WindowsFeature Multipath-IO -includeManagementTools
    }
    1 {
        "You selected No, moving along."
    }
}

# Build menu for renaming the computer
$title = "Rename the Computer?"
$currentname = Get-WmiObject Win32_ComputerSystem
$message = "Do you want to change the name of the computer? Current Name: " + $env:computername

$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
    "Renames the computer."

$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
    "Retains current system name."

$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
{
    0 {
        # Rename Computer
        Write-Host "Renaming Computer..."
        $newname = Read-Host -Prompt "Please enter the new Computer Name"
        $currentname.Rename($newname)
    }
    1 {
        "You selected No, moving along."
    }
}

# Build menu for renaming Admin user
$title = "Rename Admin User"
$message = "Select which name you'd like for the Admin user"

$1 = New-Object System.Management.Automation.Host.ChoiceDescription "&admin1", `
    "Renames Admin user to 'admin1'"

$2 = New-Object System.Management.Automation.Host.ChoiceDescription "&admin2", `
    "Renames Admin user to 'admin2'"

$options = [System.Management.Automation.Host.ChoiceDescription[]]($1, $2)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
{
    0 {
        # Rename Admin user to "admin1"
        Write-Host "Renaming Admin user and setting build password..."
        
        # Prompt for new password twice and make sure they match
        Do{
            $newpass = Read-Host -AsSecureString "Please enter the new Admin Password"
            $newpass2 = Read-Host -AsSecureString "Please re-enter the new Admin Password"
            $decodedpass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($newpass))
            $decodedpass2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($newpass2))
            if ($decodedpass -ceq $decodedpass2)
            {
                Write-Host "Passwords matched, accepted."
            }
            else {Write-Host "Passwords don't match, re-prompting"}
        }
        While ($decodedpass -cne $decodedpass2)

        ([ADSI]"WinNT://localhost/administrator").SetPassword($decodedpass)
        $user = Get-WMIObject Win32_UserAccount -Filter "Name='administrator'"
        $user.PasswordExpires = $false
        $user.Put()
        $result = $user.Rename("admin1")
        if ($result.ReturnValue -eq 0) {
        Write-Host "Renamed Admin user to admin1."
        }
    }
    1 {
        # Rename Admin user to "admin2"
        Write-Host "Renaming Admin user and setting build password..."
        
        # Prompt for new password twice and make sure they match
        Do{
            $newpass = Read-Host -AsSecureString "Please enter the new Admin Password"
            $newpass2 = Read-Host -AsSecureString "Please re-enter the new Admin Password"
            $decodedpass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($newpass))
            $decodedpass2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($newpass2))
            if ($decodedpass -ceq $decodedpass2)
            {
                Write-Host "Passwords matched, accepted."
            }
            else {Write-Host "Passwords don't match, re-prompting"}
        }
        While ($decodedpass -cne $decodedpass2)

        ([ADSI]"WinNT://localhost/administrator").SetPassword($decodedpass)
        $user = Get-WMIObject Win32_UserAccount -Filter "Name='administrator'"
        $user.PasswordExpires = $false
        $user.Put()
        $result = $user.Rename("admin2")
        if ($result.ReturnValue -eq 0) {
        Write-Host "Renamed Admin user to admin2."
        }
    }
}

# Build menu for Activating Windows
$title = "Activate Windows"
$message = "Select a Prod or Non-Prod Key to Activate Windows."

$1 = New-Object System.Management.Automation.Host.ChoiceDescription "&Prod", `
    "Initialize any extra system disks."

$2 = New-Object System.Management.Automation.Host.ChoiceDescription "&Non-Prod", `
    "Skip extra disk initialization."

$options = [System.Management.Automation.Host.ChoiceDescription[]]($1, $2)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
{
    0 {
        # Activate with Prod Key
        slmgr -ipk XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
        Write-Host "Activating Windows with Prod Key..."
    }
    1 {
        # Activate with Non-Prod Key
        slmgr -ipk XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
        Write-Host "Activating Windows with Non-Prod Key..."
    }
}

# Build menu for Computer Restart
$title = "Restart Computer?"
$message = "Are you ready to restart computer?"

$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
    "Reboot the Computer."

$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
    "Don't Reboot the Computer."

$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
{
    0 {
        # Reboot the computer
        Write-Host "Restarting the Computer..."
        Stop-Log
        Restart-Computer
    }
    1 {
        "You selected No, moving along."
        Stop-Log
    }
}
