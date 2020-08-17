<#
.SYNOPSIS
    Deletes an Always On VPN user tunnel connection

.PARAMETER ProfileName
    Name of the VPN profile to be deleted

.EXAMPLE
    .\Remove-AovpnUserTunnel.ps1 -ProfileName "Always On VPN User Tunnel"

.DESCRIPTION
    This script will delete an Always On VPN user tunnel on supported Windows 10 devices

.LINK
    https://github.com/ConfigJon/AlwaysOnVPN/blob/master/Remove-AovpnUserTunnel.ps1

.NOTES
    Creation Date:      August 17, 2020
#>

[CmdletBinding()]

Param(
    [Parameter(Mandatory = $False, HelpMessage = 'Enter the name of the VPN profile to delete.')]        
    [string]$ProfileName = 'Always On VPN User Tunnel'
)

#Variables ============================================================================================================
$RegKey = "SOFTWARE\ConfigJon"
$RegValue = "AOVPNUserTunnelVersion"

#Functions ============================================================================================================

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
		[string]$FileName = "Remove-AOVPN-User.log"
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
    $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""Remove-AOVPN"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
		
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

Write-LogEntry -Value "START - Always On VPN User Tunnel Removal Script" -Severity 1

#Escape spaces in the profile name
$ProfileNameEscaped = $ProfileName -replace ' ', '%20'

#OMA URI information
$NamespaceName = 'root\cimv2\mdm\dmmap'
$ClassName = 'MDM_VPNv2_01'

#Get the SID of the current user
try
{
    Write-LogEntry -Value "Find the SID of the currently logged on user" -Severity 1
    $Username = Get-WmiObject -Class Win32_ComputerSystem | Select-Object username
    $User = New-Object System.Security.Principal.NTAccount($Username.Username)
    $Sid = $User.Translate([System.Security.Principal.SecurityIdentifier])
    $SidValue = $Sid.Value
}
catch [Exception]
{
    $ErrorMessage = "Unable to get user SID. User may be logged on over Remote Desktop: $_"
    Write-LogEntry -Value $ErrorMessage -Severity 3
    throw $ErrorMessage
}
Write-LogEntry -Value "Successfully found the user SID: $SidValue ($User)" -Severity 1

#Create a new CimSession
$Session = New-CimSession
$Options = New-Object Microsoft.Management.Infrastructure.Options.CimOperationOptions
$Options.SetCustomOption('PolicyPlatformContext_PrincipalContext_Type', 'PolicyPlatform_UserContext', $false)
$Options.SetCustomOption('PolicyPlatformContext_PrincipalContext_Id', "$SidValue", $false)

#Remove previous versions of the user tunnel
try
{
    Write-LogEntry -Value "Check for and remove instance(s) of the user tunnel" -Severity 1
	$DeleteInstances = $Session.EnumerateInstances($NamespaceName, $ClassName, $Options)
	foreach($DeleteInstance in $DeleteInstances)
	{
		$InstanceId = $DeleteInstance.InstanceID
		if($InstanceId -eq $ProfileNameEscaped)
		{
			$Session.DeleteInstance($NamespaceName, $DeleteInstance, $Options)
            Write-LogEntry -Value "Removed $ProfileName profile $InstanceId" -Severity 1
		}
		else
		{
            Write-LogEntry -Value "Ignoring existing VPN profile $InstanceId" -Severity 2
		}
	}
}
catch [Exception]
{
    $ErrorMessage = "Unable to remove existing instance(s) of $ProfileName profile: $_"
    Write-LogEntry -Value $ErrorMessage -Severity 3
	throw $ErrorMessage
}

#Delete the registry key used for the detection method
Write-LogEntry -Value "Delete the registry key used for the detection method" -Severity 1
New-PSDrive -PSProvider registry -Root HKEY_USERS -Name HKU
if(Get-ItemProperty -Path "HKU:\$($sidvalue)\$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue)
{
    Remove-ItemProperty "HKU:\$($sidvalue)\$($RegKey)" -Name $RegValue -Force
}
Remove-PSDrive -Name HKU
Write-LogEntry -Value "END - Always On VPN User Tunnel Removal Script" -Severity 1