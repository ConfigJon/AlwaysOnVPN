<#
.SYNOPSIS
    Creates an Always On VPN device tunnel connection

.PARAMETER xmlFilePath
    Path to the ProfileXML configuration file

.PARAMETER ProfileName
    Name of the VPN profile to be created

.EXAMPLE
    .\New-AovpnDeviceTunnel.ps1 -xmlFilePath "C:\Temp\Device.xml" -ProfileName "Always On VPN Device Tunnel"

.DESCRIPTION
    This script will create an Always On VPN device tunnel on supported Windows 10 devices

.LINK
    https://github.com/ConfigJon/AlwaysOnVPN/blob/master/New-AovpnDeviceTunnel.ps1

.NOTES
    Creation Date:      May 28, 2019
    Last Updated:       August 17, 2020
    Note:               This is a modified version of a script that Richard Hicks has on his GitHub
    Original Script:    https://github.com/richardhicks/aovpn/blob/master/New-AovpnDeviceConnection.ps1
#>

[CmdletBinding()]

Param(
    [Parameter(Mandatory = $True, HelpMessage = 'Enter the path to the ProfileXML file.')]    
    [string]$xmlFilePath,
    [Parameter(Mandatory = $False, HelpMessage = 'Enter a name for the VPN profile.')]        
    [string]$ProfileName = 'Always On VPN Device Tunnel'
)

#Variables ============================================================================================================
$RegKey = "SOFTWARE\ConfigJon"
$RegValue = "AOVPNDeviceTunnelVersion"
$DeviceTunnelVersion = 1

#Functions ============================================================================================================
Function New-RegistryValue
{
    [CmdletBinding()]
    param(   
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$RegKey,
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Name,
        [String][parameter(Mandatory=$true)][ValidateSet('String','ExpandString','Binary','DWord','MultiString','Qword','Unknown')]$PropertyType,
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Value
    )
        
    #Create the registry key if it does not exist
    if(!(Test-Path $RegKey))
    {
        try{New-Item -Path $RegKey -Force | Out-Null}
        catch{throw "Failed to create $RegKey"}
    }

    #Create the registry value
    try
    {
        New-ItemProperty -Path $RegKey -Name $Name -PropertyType $PropertyType -Value $Value -Force | Out-Null
    }
    catch
    {
        Write-LogEntry -Value "Failed to set $RegKey\$Name to $Value" -Severity 3
        throw "Failed to set $RegKey\$Name to $Value"
    }

    #Check if the registry value was successfully created
    $KeyCheck = Get-ItemProperty $RegKey
    if($KeyCheck.$Name -eq $Value)
    {
        Write-LogEntry -Value "Successfully set $RegKey\$Name to $Value" -Severity 1
    }
    else
    {
        Write-LogEntry -Value "Failed to set $RegKey\$Name to $Value" -Severity 3
        throw "Failed to set $RegKey\$Name to $Value"
    }
}

#Write data to a CMTrace compatible log file. (Credit to SCConfigMgr - https://www.scconfigmgr.com/)
Function Write-LogEntry
{
	param(
		[parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
		[ValidateNotNullOrEmpty()]
		[string]$Value,
		[parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("1", "2", "3")]
		[string]$Severity,
		[parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
		[ValidateNotNullOrEmpty()]
		[string]$FileName = "Install-AOVPN-Device.log"
	)
    #Determine log file location
    $LogFilePath = Join-Path -Path $LogsDirectory -ChildPath $FileName
		
    #Construct time stamp for log entry
    if(-not(Test-Path -Path 'variable:global:TimezoneBias'))
    {
        [string]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
        if($TimezoneBias -match "^-")
        {
            $TimezoneBias = $TimezoneBias.Replace('-', '+')
        }
        else
        {
            $TimezoneBias = '-' + $TimezoneBias
        }
    }
    $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)
		
    #Construct date for log entry
    $Date = (Get-Date -Format "MM-dd-yyyy")
		
    #Construct context for log entry
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
		
    #Construct final log entry
    $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""Install-AOVPN"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
		
    #Add value to log file
    try
    {
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
    }
    catch [System.Exception]
    {
        Write-Warning -Message "Unable to append log entry to $FileName file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }
}

#Main Program =========================================================================================================

#Set the log directory
$LogsDirectory = "$ENV:ProgramData\AOVPN"
if(!(Test-Path -PathType Container $LogsDirectory))
{
    New-Item -Path $LogsDirectory -ItemType "Directory" -Force | Out-Null
}

Write-LogEntry -Value "START - Always On VPN Device Tunnel Script" -Severity 1


#Script must be running in the context of the SYSTEM account to extract ProfileXML from a device tunnel connection. Validate user, exit if not running as SYSTEM
Write-LogEntry -Value "Detect if the script is being run in the SYSTEM context" -Severity 1
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$CurrentUserName = $CurrentPrincipal.Identities.Name

if($CurrentUserName -ne 'NT AUTHORITY\SYSTEM')
{
    Write-LogEntry -Value "This script is not running in the SYSTEM context" -Severity 3
    Write-LogEntry -Value "Use the Sysinternals tool Psexec.exe with the -i and -s parameters to run this script in the context of the local SYSTEM account." -Severity 3
    throw "This script is not running in the SYSTEM context"
}

#Check for existing connection and remove if found
Write-LogEntry -Value "Check for and remove old instances of the device tunnel" -Severity 1
$Count = 0
while((Get-VpnConnection -Name $ProfileName -AllUserConnection -ErrorAction SilentlyContinue) -and ($Count -lt 20))
{
    Write-LogEntry -Value "Existing device tunnel detected. Attempt to disconnect and remove ($($Count + 1)/20)" -Severity 1
    # Disconnect the tunnel
    rasdial.exe $ProfileName /disconnect | Out-Null
    # Delete the tunnel
    Get-VpnConnection -Name $ProfileName -AllUserConnection | Remove-VpnConnection -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $Count++
}

#Exit if the loop fails to delete the tunnel
if(Get-VpnConnection -Name $ProfileName -AllUserConnection -ErrorAction SilentlyContinue)
{
    $ErrorMessage = "Unable to remove existing outdated instance(s) of $ProfileName"
    Write-LogEntry -Value $ErrorMessage -Severity 3
    throw $ErrorMessage
}

#Import the Profile XML
Write-LogEntry -Value "Import the device profile XML" -Severity 1
$ProfileXML = Get-Content $xmlFilePath

#Escape spaces in the profile name
$ProfileNameEscaped = $ProfileName -replace ' ', '%20'
$ProfileXML = $ProfileXML -replace '<', '&lt;'
$ProfileXML = $ProfileXML -replace '>', '&gt;'
$ProfileXML = $ProfileXML -replace '"', '&quot;'

#OMA URI information
$NodeCSPURI = './Vendor/MSFT/VPNv2'
$NamespaceName = 'root\cimv2\mdm\dmmap'
$ClassName = 'MDM_VPNv2_01'

#Create a new CimSession
$Session = New-CimSession

#Create the device tunnel
$Error.Clear()
try
{
    Write-LogEntry -Value "Construct a new CimInstance object" -Severity 1
    $NewInstance = New-Object Microsoft.Management.Infrastructure.CimInstance $ClassName, $NamespaceName
    $Property = [Microsoft.Management.Infrastructure.CimProperty]::Create('ParentID', "$nodeCSPURI", 'String', 'Key')
    $NewInstance.CimInstanceProperties.Add($Property)
    $Property = [Microsoft.Management.Infrastructure.CimProperty]::Create('InstanceID', "$ProfileNameEscaped", 'String', 'Key')
    $NewInstance.CimInstanceProperties.Add($Property)
    $Property = [Microsoft.Management.Infrastructure.CimProperty]::Create('ProfileXML', "$ProfileXML", 'String', 'Property')
    $NewInstance.CimInstanceProperties.Add($Property)
    Write-LogEntry -Value "Create the new device tunnel" -Severity 1
    $Session.CreateInstance($NamespaceName, $NewInstance)
    Write-LogEntry -Value "Always On VPN device tunnel ""$ProfileName"" created successfully." -Severity 1
}
catch [Exception]
{
    $ErrorMessage = "Unable to create $ProfileName profile: $_"
    Write-LogEntry -Value $ErrorMessage -Severity 3
    throw $ErrorMessage
}

#Configure enchanced IKEv2 security settings
#Set-VpnConnectionIPsecConfiguration -ConnectionName $ProfileName -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES128 -DHGroup Group14 -EncryptionMethod AES128 -IntegrityCheckMethod SHA256 -PFSgroup PFS2048 -Force

#Create a registry key for detection
if(!($Error))
{
    Write-LogEntry -Value "Create the registry key to use for the detection method" -Severity 1
    #Create a registry key for detection
    New-RegistryValue -RegKey "HKLM:\$($RegKey)" -Name $RegValue -PropertyType DWord -Value $DeviceTunnelVersion
}
Write-LogEntry -Value "END - Always On VPN Device Tunnel Script" -Severity 1