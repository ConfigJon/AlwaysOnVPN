<#
.SYNOPSIS
    Deletes an Always On VPN device tunnel connection

.PARAMETER ProfileName
    Name of the VPN profile to be deleted

.EXAMPLE
    .\Remove-AovpnDeviceTunnel.ps1 -ProfileName "Always On VPN Device Tunnel"

.DESCRIPTION
    This script will delete an Always On VPN device tunnel on supported Windows 10 devices

.LINK
    https://github.com/ConfigJon/AlwaysOnVPN/blob/master/Remove-AovpnDeviceTunnel.ps1

.NOTES
    Creation Date:      August 17, 2020
#>

[CmdletBinding()]

Param(
    [Parameter(Mandatory = $False, HelpMessage = 'Enter the name of the VPN profile to delete.')]        
    [string]$ProfileName = 'Always On VPN Device Tunnel'
)

#Variables ============================================================================================================
$RegKey = "SOFTWARE\ConfigJon"
$RegValue = "AOVPNDeviceTunnelVersion"

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
		[string]$FileName = "Remove-AOVPN-Device.log"
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

Write-LogEntry -Value "START - Always On VPN Device Tunnel Removal Script" -Severity 1


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
Write-LogEntry -Value "Check for and remove instance(s) of the device tunnel" -Severity 1
if(Get-VpnConnection -Name $ProfileName -AllUserConnection -ErrorAction SilentlyContinue)
{
    $Count = 0
    while((Get-VpnConnection -Name $ProfileName -AllUserConnection -ErrorAction SilentlyContinue) -and ($Count -lt 20))
    {
        Write-LogEntry -Value "Existing device tunnel detected. Attempt to disconnect and remove ($($Count + 1)/20)" -Severity 1
        #Disconnect the tunnel
        rasdial.exe $ProfileName /disconnect | Out-Null
        #Delete the tunnel
        Get-VpnConnection -Name $ProfileName -AllUserConnection | Remove-VpnConnection -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $Count++
    }

    #Exit if the loop fails to delete the tunnel
    if(Get-VpnConnection -Name $ProfileName -AllUserConnection -ErrorAction SilentlyContinue)
    {
        $ErrorMessage = "Unable to remove existing instance(s) of $ProfileName"
        Write-LogEntry -Value $ErrorMessage -Severity 3
        throw $ErrorMessage
    }
    else
    {
        Write-LogEntry -Value "Succefully removed the existing instance of $ProfileName" -Severity 1
    }
}
else
{
    Write-LogEntry -Value "Unable to find device tunnel instance matching $ProfileName" -Severity 2
}

#Delete the registry key used for the detection method
Write-LogEntry -Value "Delete the registry key used for the detection method" -Severity 1
if(Get-ItemProperty -Path "HKLM:\$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue)
{
    Remove-ItemProperty "HKLM:\$($RegKey)" -Name $RegValue -Force
}
Write-LogEntry -Value "END - Always On VPN Device Tunnel Removal Script" -Severity 1