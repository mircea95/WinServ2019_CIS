#WINDOWS SID CONSTANTS
#https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
$SID_NOONE = "`"`""
$SID_ADMINISTRATORS = "*S-1-5-32-544"
$SID_GUESTS = "*S-1-5-32-546"
$SID_SERVICE = "*S-1-5-6"
$SID_NETWORK_SERVICE = "*S-1-5-20"
$SID_LOCAL_SERVICE = "*S-1-5-19"
$SID_LOCAL_ACCOUNT = "*S-1-5-113"
$SID_WINDOW_MANAGER_GROUP = "*S-1-5-90-0"
$SID_REMOTE_DESKTOP_USERS = "*S-1-5-32-555"
$SID_VIRTUAL_MACHINE = "*S-1-5-83-0"
$SID_AUTHENTICATED_USERS = "*S-1-5-11"
$SID_WDI_SYSTEM_SERVICE = "*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
$SID_BACKUP_OPERATORS = "*S-1-5-32-551"
$SID_ENT_DOM_CONTROL = "*S-1-5-9"
$SID_MEM_OF_ADMINGROUP = "*S-1-5-114"
##########################################################################################################
##1 Account Policies
##1.1 Password Policy
function _1.1.1.EnforcePasswordHistory
{
    $stat = 'Fail'
    Write-Host "1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'"
	if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
		$val = NET ACCOUNTS /DOMAIN | Select-String -SimpleMatch 'Length of password history maintained'
	} else {
		$val = net accounts | Select-String -SimpleMatch 'Length of password history maintained'
	}
    Write-Host "Command:  net accounts | Select-String -SimpleMatch 'Length of password history maintained'"
    Write-Host "Command result: "$val
    #$val -match '\d\d' | out-null
    If($val -match '\d+' -and $Matches.0 -ge 24){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _1.1.2.MaximumPasswordAge
{
    $stat = 'Fail'
    Write-Host "1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'"
	if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
		$val = NET ACCOUNTS /DOMAIN | Select-String -SimpleMatch 'Maximum password age'
	} else {
		$val = net accounts | Select-String -SimpleMatch 'Maximum password age'
	}
    Write-Host "Command:  net accounts | Select-String -SimpleMatch 'Maximum password age'"
    Write-Host "Command result: "$val
    If($val -match '\d+' -and $Matches.0 -le 60 -and $Matches.0 -gt 0){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _1.1.3.MinimumPasswordAge
{
    $stat = 'Fail'
    Write-Host "1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'"
	if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
		$val = NET ACCOUNTS /DOMAIN | Select-String -SimpleMatch 'Minimum password age'
	} else {
		$val = net accounts | Select-String -SimpleMatch 'Minimum password age'
	}
    Write-Host "Command:  net accounts | Select-String -SimpleMatch 'Minimum password age'"
    Write-Host "Command result: "$val
    If($val -match '\d+' -and $Matches.0 -ge 1){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _1.1.4.MinimumPasswordLength
{
    $stat = 'Fail'
    Write-Host "1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'"
	if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
		$val = NET ACCOUNTS /DOMAIN | Select-String -SimpleMatch 'Minimum password length'
	} else {
		$val = net accounts | Select-String -SimpleMatch 'Minimum password length'
	}
    Write-Host "Command:  net accounts | Select-String -SimpleMatch 'Minimum password length'"
    Write-Host "Command result: "$val
    If($val -match '\d+' -and $Matches.0 -ge 14){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _1.1.5.WindowsPasswordComplexityPolicyMustBeEnabled
{
    $stat = 'Fail'
    Write-Host "1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'PasswordComplexity'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'PasswordComplexity'"
    Write-Host "Command result: "$val
    If($val -match '\d+' -and $Matches.0 -eq 1){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _1.1.6.DisablePasswordReversibleEncryption
{
    $stat = 'Fail'
    Write-Host "1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'ClearTextPassword'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'ClearTextPassword'"
    Write-Host "Command result: "$val
    If($val -match '\d+' -and $Matches.0 -eq 0){$stat = "Pass"}
        
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##1.2 Account Lockout Policy
function _1.2.1.AccountLockoutDuration
{
    $stat = 'Fail'
    Write-Host "1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'"
	if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
		$val = NET ACCOUNTS /DOMAIN | Select-String -SimpleMatch 'lockout duration'
	} else {
		$val = net accounts | Select-String -SimpleMatch 'lockout duration'
	}
    Write-Host "Command:  net accounts | Select-String -SimpleMatch 'lockout duration'"
    Write-Host "Command result: "$val
    If($val -match '\d+' -and $Matches.0 -ge 15){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _1.2.2.AccountLockoutThreshold
{
    $stat = 'Fail'
    Write-Host "1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'"
	if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
		$val = NET ACCOUNTS /DOMAIN | Select-String -SimpleMatch 'lockout threshold'
	} else {
		$val = net accounts | Select-String -SimpleMatch 'lockout threshold'
	}
    Write-Host "Command:  net accounts | Select-String -SimpleMatch 'lockout threshold'"
    Write-Host "Command result: "$val
    #cind se compara valoare cu un caracter cu valoarea 10, atunci se compara cu prima cifra a valoarei 10, adica 1(TO CHECK)--am pus 9)))
    If($val -match '\d+' -and $Matches.0 -le 9 -and $Matches.0 -gt 0){$stat = "Pass"} 
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _1.2.3.ResetAccountLockoutCounter
{
    $stat = 'Fail'
    Write-Host "1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
	if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
		$val = NET ACCOUNTS /DOMAIN | Select-String -SimpleMatch 'Lockout observation window'
	} else {
		$val = net accounts | Select-String -SimpleMatch 'Lockout observation window'
	}
    Write-Host "Command:  net accounts | Select-String -SimpleMatch 'Lockout observation window'"
    Write-Host "Command result: "$val
    If($val -match '\d+' -and $Matches.0 -ge 15){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2 Local Policies
##2.1 Audit Policy
##2.2 User Rights Assignment
function _2.2.1.NoOneTrustCallerACM
{
    $stat = 'Fail'
    Write-Host "2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTrustedCredManAccessPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTrustedCredManAccessPrivilege'"
    
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"; $stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.2.AccessComputerFromNetworkDC
{
    $stat = 'Fail'
    Write-Host "2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeNetworkLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeNetworkLogonRight'"
    
    $rght = $SID_AUTHENTICATED_USERS + ',' + $SID_ADMINISTRATORS + ',' + $SID_ENT_DOM_CONTROL
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.3.AccessComputerFromNetwork
{
    $stat = 'Fail'
    Write-Host "2.2.3 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeNetworkLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeNetworkLogonRight'"
    
    $rght = $SID_AUTHENTICATED_USERS + ',' + $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.4.NoOneActAsPartOfOperatingSystem
{
    $stat = 'Fail'
    Write-Host "2.2.4 (L1) Ensure 'Act as part of the operating system' is set to 'No One'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTcbPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTcbPrivilege'"
    
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"; $stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.5.AccessAddWorkstationsDC
{
    $stat = 'Fail'
    Write-Host "2.2.5 (L1) Ensure 'Add workstations to domain' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeMachineAccountPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeMachineAccountPrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.6.AccessComputerFromNetwork
{
    $stat = 'Fail'
    Write-Host "2.2.6 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeIncreaseQuotaPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeIncreaseQuotaPrivilege'"
    
    $rght = $SID_LOCAL_SERVICE + ',' + $SID_NETWORK_SERVICE + ',' + $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.7.AllowLogonLocallyToAdministrators
{
    $stat = 'Fail'
    Write-Host "2.2.7 (L1) Ensure 'Allow log on locally' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeInteractiveLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeInteractiveLogonRight'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.8.LogonThroughRemoteDesktopServicesDC
{
    $stat = 'Fail'
    Write-Host "2.2.8 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRemoteInteractiveLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRemoteInteractiveLogonRight'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.9.LogonThroughRemoteDesktopServices
{
    $stat = 'Fail'
    Write-Host "2.2.9 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRemoteInteractiveLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRemoteInteractiveLogonRight'"
    
    $rght = $SID_ADMINISTRATORS + ',' + $SID_REMOTE_DESKTOP_USERS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.10.BackupFilesAndDirectories
{
    $stat = 'Fail'
    Write-Host "2.2.10 (L1) Ensure 'Back up files and directories' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeBackupPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeBackupPrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.11.ChangeSystemTime
{
    $stat = 'Fail'
    Write-Host "2.2.11 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSystemtimePrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSystemtimePrivilege'"
    
    $rght = $SID_LOCAL_SERVICE + ',' + $SID_ADMINISTRATORS 
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.12.ChangeTimeZone
{
    $stat = 'Fail'
    Write-Host "2.2.12 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTimeZonePrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTimeZonePrivilege'"
    
    $rght = $SID_LOCAL_SERVICE + ',' + $SID_ADMINISTRATORS 
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.13.CreatePagefile
{
    $stat = 'Fail'
    Write-Host "2.2.13 (L1) Ensure 'Create a pagefile' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreatePagefilePrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreatePagefilePrivilege'"
    
    $rght = $SID_ADMINISTRATORS 
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.14.NoOneCreateTokenObject
{
    $stat = 'Fail'
    Write-Host "2.2.14 (L1) Ensure 'Create a token object' is set to 'No One'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateTokenPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateTokenPrivilege'"
    
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"; $stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.15.CreatePagefile
{
    $stat = 'Fail'
    Write-Host "2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateGlobalPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateGlobalPrivilege'"
    
    $rght = $SID_LOCAL_SERVICE + ',' + $SID_NETWORK_SERVICE + ',' + $SID_ADMINISTRATORS + ',' + $SID_SERVICE
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.16.NoOneCreateTokenObject
{
    $stat = 'Fail'
    Write-Host "2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreatePermanentPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreatePermanentPrivilege'"
    
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"; $stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.17.CreateSymbolicLinksDC
{
    $stat = 'Fail'
    Write-Host "2.2.17 (L1) Ensure 'Create symbolic links' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateSymbolicLinkPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateSymbolicLinkPrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.18.CreateSymbolicLinks
{
    $stat = 'Fail'
    Write-Host "2.2.18 (L1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateSymbolicLinkPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateSymbolicLinkPrivilege'"
    
    $rght = $SID_ADMINISTRATORS + ',' + $SID_VIRTUAL_MACHINE
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.19.DebugPrograms
{
    $stat = 'Fail'
    Write-Host "2.2.19 (L1) Ensure 'Debug programs' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDebugPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDebugPrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.20.DenyNetworkAccessDC
{
    $stat = 'Fail'
    Write-Host "2.2.20 (L1) Ensure 'Deny access to this computer from the network' to include 'Guests'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyNetworkLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyNetworkLogonRight'"
    
    $rght = $SID_GUESTS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.21.DenyNetworkAccess
{
    $stat = 'Fail'
    Write-Host "2.2.21 (L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account and member of Administrators group'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyNetworkLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyNetworkLogonRight'"
    
    #Nu este sigur ce reprezinta Administrators group
    $rght = $SID_LOCAL_ACCOUNT + ',' + $SID_MEM_OF_ADMINGROUP + ',' + $SID_GUESTS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.22.DenyGuestBatchLogon
{
    $stat = 'Fail'
    Write-Host "2.2.22 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyBatchLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyBatchLogonRight'"
    
    $rght = $SID_GUESTS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.23.DenyGuestServiceLogon
{
    $stat = 'Fail'
    Write-Host "2.2.23 (L1) Ensure 'Deny log on as a service' to include 'Guests'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyServiceLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyServiceLogonRight'"
    
    $rght = $SID_GUESTS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.24.DenyGuestLocalLogon
{
    $stat = 'Fail'
    Write-Host "2.2.24 (L1) Ensure 'Deny log on locally' to include 'Guests'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyInteractiveLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyInteractiveLogonRight'"
    
    $rght = $SID_GUESTS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.25.DenyRemoteDesktopServiceLogonDC
{
    $stat = 'Fail'
    Write-Host "2.2.25 (L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyRemoteInteractiveLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyRemoteInteractiveLogonRight'"
    
    $rght = $SID_GUESTS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.26.DenyRemoteDesktopServiceLogon
{
    $stat = 'Fail'
    Write-Host "2.2.26 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyRemoteInteractiveLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyRemoteInteractiveLogonRight'"
    
    $rght = $SID_LOCAL_ACCOUNT + ',' + $SID_GUESTS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.27.AdminTrustedForDelegationDC
{
    $stat = 'Fail'
    Write-Host "2.2.27 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDelegateSessionUserImpersonatePrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDelegateSessionUserImpersonatePrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.28.NoOneTrustedForDelegation
{
    $stat = 'Fail'
    Write-Host "2.2.28 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDelegateSessionUserImpersonatePrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDelegateSessionUserImpersonatePrivilege'"
    
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"; $stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.29.ForceShutdownFromRemoteSystem
{
    $stat = 'Fail'
    Write-Host "2.2.29 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRemoteShutdownPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRemoteShutdownPrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.30.GenerateSecurityAudits
{
    $stat = 'Fail'
    Write-Host "2.2.30 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeAuditPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeAuditPrivilege'"
    
    $rght = $SID_LOCAL_SERVICE + ',' + $SID_NETWORK_SERVICE
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.31.ImpersonateClientAfterAuthenticationDC
{
    $stat = 'Fail'
    Write-Host "2.2.31 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeImpersonatePrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeImpersonatePrivilege'"
    
    $rght = $SID_LOCAL_SERVICE + ',' + $SID_NETWORK_SERVICE + ',' + $SID_ADMINISTRATORS + ',' + $SID_SERVICE
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.32.ImpersonateClientAfterAuthentication
{
    $stat = 'Fail'
    Write-Host "2.2.32 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeImpersonatePrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeImpersonatePrivilege'"
    
    #Pe Win server de verificat daca e insatla IIS, daca da atunci se adauga si IIS_IUSRS (To check)
    $rght = $SID_LOCAL_SERVICE + ',' + $SID_NETWORK_SERVICE + ',' + $SID_ADMINISTRATORS + ',' + $SID_SERVICE
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.33.IncreaseSchedulingPriority
{
    $stat = 'Fail'
    Write-Host "2.2.33 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeIncreaseBasePriorityPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeIncreaseBasePriorityPrivilege'"
    
    $rght = $SID_ADMINISTRATORS + ',' + $SID_WINDOW_MANAGER_GROUP
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.34.LoadUnloadDeviceDrivers
{
    $stat = 'Fail'
    Write-Host "2.2.34 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeLoadDriverPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeLoadDriverPrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.35.NoOneLockPagesInMemory
{
    $stat = 'Fail'
    Write-Host "2.2.35 (L1) Ensure 'Lock pages in memory' is set to 'No One'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeLockMemoryPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeLockMemoryPrivilege'"
    
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"; $stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.36.LogBatchJobToAdminDC
{
    $stat = 'Fail'
    Write-Host "2.2.36 (L2) Ensure 'Log on as a batch job' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeBatchLogonRight'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeBatchLogonRight'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.37.ManageAuditingAndSecurityDC
{
    $stat = 'Fail'
    Write-Host "2.2.37 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators' and (when Exchange is running in the environment) 'Exchange Servers'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSecurityPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSecurityPrivilege'"
    
    #when Exchange is running in the environment atunci de adaugat la drepturi si Exchange Servers (TO CHECK)
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.38.ManageAuditingAndSecurity
{
    $stat = 'Fail'
    Write-Host "2.2.38 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSecurityPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSecurityPrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.39.NoOneModifiesObjectLabel
{
    $stat = 'Fail'
    Write-Host "2.2.39 (L1) Ensure 'Modify an object label' is set to 'No One'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRelabelPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRelabelPrivilege'"
    
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"; $stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.40.FirmwareEnvValues
{
    $stat = 'Fail'
    Write-Host "2.2.40 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSystemEnvironmentPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSystemEnvironmentPrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.41.VolumeMaintenance
{
    $stat = 'Fail'
    Write-Host "2.2.41 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeManageVolumePrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeManageVolumePrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.42.ProfileSingleProcess
{
    $stat = 'Fail'
    Write-Host "2.2.42 (L1) Ensure 'Profile single process' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeProfileSingleProcessPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeProfileSingleProcessPrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.43.ProfileSystemPerformance
{
    $stat = 'Fail'
    Write-Host "2.2.43 (L1) Ensure 'Profile system performance' is set to 'Administrators,NT SERVICE\WdiServiceHost'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSystemProfilePrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSystemProfilePrivilege'"
    
    $rght = $SID_ADMINISTRATORS + ',' + $SID_WDI_SYSTEM_SERVICE
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.44.ReplaceProcessLevelToken
{
    $stat = 'Fail'
    Write-Host "2.2.44 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeAssignPrimaryTokenPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeAssignPrimaryTokenPrivilege'"
    
    $rght = $SID_LOCAL_SERVICE + ',' + $SID_NETWORK_SERVICE
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.45.RestoreFilesDirectories
{
    $stat = 'Fail'
    Write-Host "2.2.45 (L1) Ensure 'Restore files and directories' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRestorePrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRestorePrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.46.RestoreFilesDirectories
{
    $stat = 'Fail'
    Write-Host "2.2.46 (L1) Ensure 'Shut down the system' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeShutdownPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeShutdownPrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.47.NoOneSynchDirServDataDC
{
    $stat = 'Fail'
    Write-Host "2.2.47 (L1) Ensure 'Synchronize directory service data' is set to 'No One'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSyncAgentPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSyncAgentPrivilege'"
    
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"; $stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.2.48.TakeOwnershipFiles
{
    $stat = 'Fail'
    Write-Host "2.2.48 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTakeOwnershipPrivilege'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTakeOwnershipPrivilege'"
    
    $rght = $SID_ADMINISTRATORS
    If($val){
        Write-Host "Command result: "$val
        If($val -match '.S-.+.\d$' -and $Matches.0 -eq $rght){$stat = "Pass"}}
    Else{
        Write-Host "Command result: No One"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3 Security Options
##2.3.1 Accounts
function _2.3.1.1.DisableAdministratorAccount
{
    $stat = 'Fail'
    Write-Host "2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'EnableAdminAccount'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'EnableAdminAccount'"
    Write-Host "Command result: "$val
    If($val -match '\d+' -and $Matches.0 -eq 0){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.1.2.DisableMicrosoftAccounts
{
    $stat = 'Fail'
    Write-Host "2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
	
    $loc = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    Write-Host "Command result: "$val
    If($val -match '\d.+' -and $Matches.0 -eq '4,3'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.1.3.DisableGuestAccount
{
    $stat = 'Fail'
    Write-Host "2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'"
	
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'EnableGuestAccount'
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'EnableGuestAccount'"
    Write-Host "Command result: "$val
    If($val -match '\d+' -and $Matches.0 -eq 0){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.1.4.LimitBlankPasswordConsole
{
    $stat = 'Fail'
    Write-Host "2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    Write-Host "Command result: "$val
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.1.5.RenameAdministratorAccount
{
    $stat = 'Fail'
    Write-Host "2.3.1.5 (L1) Configure 'Accounts: Rename administrator account'"
	
    $loc = "NewAdministratorName"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    Write-Host "Command result: "$val
    If($val -match '".+$' -and $Matches.0 -notlike '"Administrator"'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.1.6.RenameGuestAccount
{
    $stat = 'Fail'
    Write-Host "2.3.1.6 (L1) Configure 'Accounts: Rename guest account'"
	
    $loc = "NewGuestName"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    Write-Host "Command result: "$val
    If($val -match '".+$' -and $Matches.0 -notlike '"Guest"'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3.2 Audit
function _2.3.2.1.AuditForceSubCategoryPolicy
{
    $stat = 'Fail'
    Write-Host "2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings to override audit policy category settings' is set to 'Enabled'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.2.2.AuditForceShutdown
{
    $stat = 'Fail'
    Write-Host "2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3.3 DCOM
##2.3.4 Devices
function _2.3.4.1.DevicesAdminAllowedFormatEject
{
    $stat = 'Fail'
    Write-Host "2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'"
	
    $loc = 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '1,"0"'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.4.2.PreventPrinterInstallation
{
    $stat = 'Fail'
    Write-Host "2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3.5 Domain controller
function _2.3.5.1.AlowServOperToSchedTasksDisDC
{
    $stat = 'Fail'
    Write-Host "2.3.5.1 (L1) Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Control\Lsa\SubmitControl'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.5.2.LDAPServSetToReqSignDC
{
    $stat = 'Fail'
    Write-Host "2.3.5.2 (L1) Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,2'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.5.3.RefuseMachiAccPassChanTODisDC
{
    $stat = 'Fail'
    Write-Host "2.3.5.3 (L1) Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3.6 Domain member
function _2.3.6.1.SignEncryptAllChannelData
{
    $stat = 'Fail'
    Write-Host "2.3.6.1 (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.6.2.SecureChannelWhenPossible
{
    $stat = 'Fail'
    Write-Host "2.3.6.2 (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.6.3.DigitallySignChannelWhenPossible
{
    $stat = 'Fail'
    Write-Host "2.3.6.3 (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.6.4.EnableAccountPasswordChanges
{
    $stat = 'Fail'
    Write-Host "2.3.6.4 (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.6.5.MaximumAccountPasswordAge
{
    $stat = 'Fail'
    Write-Host "2.3.6.5 (L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,30'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.6.6.RequireStrongSessionKey
{
    $stat = 'Fail'
    Write-Host "2.3.6.6 (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'"
	
    $loc = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey'
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3.7 Interactive logon
function _2.3.7.1.RequireCtlAltDel{
    $stat = 'Fail'
    Write-Host "2.3.7.1 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.7.2.DontDisplayLastSigned{
    $stat = 'Fail'
    Write-Host "2.3.7.2 (L1) Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.7.3.MachineInactivityLimit{
    $stat = 'Fail'
    Write-Host "2.3.7.3 (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,900'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.7.4.LogonLegalNotice{
    $stat = 'Fail'
    Write-Host "2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -ne '7,'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.7.5.LogonLegalNoticeTitle{
    $stat = 'Fail'
    Write-Host "2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -ne '1,""'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.7.6.PreviousLogonCache{
    $stat = 'Fail'
    Write-Host "2.3.7.6 (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'"
	
    $loc = "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '1,"4"')
        {$stat = "Pass"}
    Else{
        $val -match '"\d+"' | out-null
        $c = $Matches.0 
        $c -match '\d+' | out-null
        $c = $Matches.0
        $c = $c -as [int]
        If($c -le 4){$stat = "Pass"}
        }
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.7.7.PromptUserPassExpiration{
    $stat = 'Fail'
    Write-Host "2.3.7.7 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"
	
    $loc = "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,5')
        {$stat = "Pass"}
    Else{
        $val -match ',\d+' | out-null
        $c = $Matches.0 
        $c -match '\d+' | out-null
        $c = $Matches.0
        $c = $c -as [int]
        If($c -ge 5 -and $c -le 14){$stat = "Pass"}
        }
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.7.8.RequireDomainControllerAuth{
    $stat = 'Fail'
    Write-Host "2.3.7.8 (L1) Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'"
	
    $loc = "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.7.9.SmartCardRemovalBehaviour{
    $stat = 'Fail'
    Write-Host "2.3.7.9 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher"
	
    $loc = "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '1,"1"')
        {$stat = "Pass"}
    Else{
        $val -match '"\d+"' | out-null
        $c = $Matches.0 
        $c -match '\d+' | out-null
        $c = $Matches.0
        $c = $c -as [int]
        If($c -ge 1){$stat = "Pass"}
        }
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3.8 Microsoft network client
function _2.3.8.1.NetworkClientSignCommunications{
    $stat = 'Fail'
    Write-Host "2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.8.2.EnableSecuritySignature{
    $stat = 'Fail'
    Write-Host "2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.8.3.DisableSmbUnencryptedPassword{
    $stat = 'Fail'
    Write-Host "2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3.9 Microsoft network server
function _2.3.9.1.IdleTimeSuspendingSession{
    $stat = 'Fail'
    Write-Host "2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,15')
        {$stat = "Pass"}
    Else{
        $val -match ',\d+' | out-null
        $c = $Matches.0 
        $c -match '\d+' | out-null
        $c = $Matches.0
        $c = $c -as [int]
        If($c -le 15){$stat = "Pass"}
        }
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.9.2.NetworkServerAlwaysDigitallySign{
    $stat = 'Fail'
    Write-Host "2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.9.3.LanManSrvEnableSecuritySignature{
    $stat = 'Fail'
    Write-Host "2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.9.4.LanManServerEnableForcedLogOff{
    $stat = 'Fail'
    Write-Host "2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.9.5.LanManServerSmbServerNameHardeningLevel{
    $stat = 'Fail'
    Write-Host "2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1' -or $Matches.0 -eq '4,2'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3.10 Network access
function _2.3.10.1.LSAAnonymousNameDisabled{
    $stat = 'Fail'
    Write-Host "2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
	
    $loc = "LSAAnonymousNameLookup"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d+' -and $Matches.0 -eq '0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.10.2.RestrictAnonymousSAM{
    $stat = 'Fail'
    Write-Host "2.3.10.2 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.10.3.RestrictAnonymous{
    $stat = 'Fail'
    Write-Host "2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc | select-object -First 1
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.10.4.DisableDomainCreds{
    $stat = 'Fail'
    Write-Host "2.3.10.4 (L2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.10.5.EveryoneIncludesAnonymous{
    $stat = 'Fail'
    Write-Host "2.3.10.5 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.10.6.NullSessionPipesDC{
    $stat = 'Fail'
    Write-Host "2.3.10.6 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously'"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '7,'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.10.7.NullSessionPipes{
    $stat = 'Fail'
    Write-Host "2.3.10.7 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously'"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '7,'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.10.8.AllowedExactPaths{
    $stat = 'Fail'
    Write-Host "2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.10.9.AllowedPaths{
    $stat = 'Fail'
    Write-Host "2.3.10.9 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '7,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.10.10.RestrictNullSessAccess{
    $stat = 'Fail'
    Write-Host "2.3.10.10 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.10.11.RestrictRemoteSAM{
    $stat = 'Fail'
    Write-Host "2.3.10.11 (L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '1,"O:BAG:BAD:(A;;RC;;;BA)"'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.10.12.NullSessionShares{
    $stat = 'Fail'
    Write-Host "2.3.10.12 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '7,'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.10.13.LsaForceGuest{
    $stat = 'Fail'
    Write-Host "2.3.10.13 (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3.11 Network security
function _2.3.11.1.LsaUseMachineId{
    $stat = 'Fail'
    Write-Host "2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.11.2.AllowNullSessionFallback{
    $stat = 'Fail'
    Write-Host "2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d,\d' -and $Matches.0 -eq '4,0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.11.3.AllowOnlineID{
    $stat = 'Fail'
    Write-Host "2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d,\d' -and $Matches.0 -eq '4,0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.11.4.SupportedEncryptionTypes{
    $stat = 'Fail'
    Write-Host "2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,2147483640'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.11.5.NoLMHash{
    $stat = 'Fail'
    Write-Host "2.3.11.5 (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.11.6.ForceLogoff{
    $stat = 'Fail'
    Write-Host "2.3.11.6 (L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'"
	
    $loc = "ForceLogoffWhenHourExpire"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d+' -and $Matches.0 -eq '1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.11.7.LmCompatibilityLevel{
    $stat = 'Fail'
    Write-Host "2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,5'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.11.8.LDAPClientIntegrity{
    $stat = 'Fail'
    Write-Host "2.3.11.8 (L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
	
    $loc = "MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.11.9.NTLMMinClientSec{
    $stat = 'Fail'
    Write-Host "2.3.11.9 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d,\d+' -and $Matches.0 -eq '4,537395200'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.11.10.NTLMMinServerSec{
    $stat = 'Fail'
    Write-Host "2.3.11.10 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d,\d+' -and $Matches.0 -eq '4,537395200'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3.12 Recovery console
##2.3.13 Shutdown
function _2.3.13.1.ShutdownWithoutLogon{
    $stat = 'Fail'
    Write-Host "2.3.13.1 (L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.\d+' -and $Matches.0 -eq '4,0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3.14 System cryptography
##2.3.15 System objects
function _2.3.15.1.ObCaseInsensitive{
    $stat = 'Fail'
    Write-Host "2.3.15.1 (L1) Ensure 'System objects: Require case insensitivity for nonWindows subsystems' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.15.2.SessionManagerProtectionMode{
    $stat = 'Fail'
    Write-Host "2.3.15.2 (L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
	
    $loc = "MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##2.3.16 System settings
##2.3.17 User Account Control
function _2.3.17.1.FilterAdministratorToken{
    $stat = 'Fail'
    Write-Host "2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.17.2.ConsentPromptBehaviorAdmin{
    $stat = 'Fail'
    Write-Host "2.3.17.2 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,2'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.17.3.ConsentPromptBehaviorUser{
    $stat = 'Fail'
    Write-Host "2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,0'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.17.4.EnableInstallerDetection{
    $stat = 'Fail'
    Write-Host "2.3.17.4 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.17.5.EnableSecureUIAPaths{
    $stat = 'Fail'
    Write-Host "2.3.17.5 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.17.6.EnableLUA{
    $stat = 'Fail'
    Write-Host "2.3.17.6 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.17.7.PromptOnSecureDesktop{
    $stat = 'Fail'
    Write-Host "2.3.17.7 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _2.3.17.8.EnableVirtualization{
    $stat = 'Fail'
    Write-Host "2.3.17.8 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
	
    $loc = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization"
    $val = Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch $loc 
    Write-Host "Command:  Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch " $loc
    If($val){Write-Host "Command result: "$val}Else{Write-Host "Command result: No One"}
    If($val -match '\d.+' -and $Matches.0 -eq '4,1'){$stat = "Pass"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##3 Event Log
##4 Restricted Groups
##5 System Services
##6 Registry
##7 File System
##8 Wired Network (IEEE 802.3) Policies
##9 Windows Firewall with Advanced Security
##9.1 Domain Profile
function _9.1.1.EnableVirtualization{
    $stat = 'Fail'
    Write-Host "9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    $reg_n = "EnableFirewall"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.1.2.DomainDefaultInboundAction{
    $stat = 'Fail'
    Write-Host "9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    $reg_n = "DefaultInboundAction"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.1.3.DomainDefaultOutboundAction{
    $stat = 'Fail'
    Write-Host "9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\"
    $reg_n = "DefaultOutboundAction"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.1.3.DomainDefaultOutboundAction{
    $stat = 'Fail'
    Write-Host "9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\"
    $reg_n = "DefaultOutboundAction"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.1.4.DomainDisableNotifications{
    $stat = 'Fail'
    Write-Host "9.1.4 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    $reg_n = "DisableNotifications"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.1.5.DomainLogFilePath{
    $stat = 'Fail'
    Write-Host "9.1.5 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    $reg_n = "LogFilePath"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -like "%SystemRoot%\System32\logfiles\firewall\domainfw.log"){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.1.6.DomainLogFileSize{
    $stat = 'Fail'
    Write-Host "9.1.6 (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    $reg_n = "LogFileSize"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -ge 16384){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.1.7.DomainLogDroppedPackets{
    $stat = 'Fail'
    Write-Host "9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    $reg_n = "LogDroppedPackets"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.1.8.DomainLogSuccessfulConnections{
    $stat = 'Fail'
    Write-Host "9.1.8 (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
    $reg_n = "LogSuccessfulConnections"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##9.2 Private Profile
function _9.2.1.PrivateEnableFirewall{
    $stat = 'Fail'
    Write-Host "9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $reg_n = "EnableFirewall"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.2.2.PrivateDefaultInboundAction{
    $stat = 'Fail'
    Write-Host "9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $reg_n = "DefaultInboundAction"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.2.3.PrivateDefaultOutboundAction{
    $stat = 'Fail'
    Write-Host "9.2.3 (L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $reg_n = "DefaultOutboundAction"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.2.4.PrivateDisableNotifications{
    $stat = 'Fail'
    Write-Host "9.2.4 (L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $reg_n = "DisableNotifications"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.2.5.PrivateLogFilePath{
    $stat = 'Fail'
    Write-Host "9.2.5 (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
    $reg_n = "LogFilePath"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -like "%SystemRoot%\System32\logfiles\firewall\privatefw.log"){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.2.6.PrivateLogFileSize{
    $stat = 'Fail'
    Write-Host "9.2.6 (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
    $reg_n = "LogFileSize"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -ge 16384){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.2.7.PrivateLogDroppedPackets{
    $stat = 'Fail'
    Write-Host "9.2.7 (L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
    $reg_n = "LogDroppedPackets"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.2.8.PrivateLogSuccessfulConnections{
    $stat = 'Fail'
    Write-Host "9.2.8 (L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
    $reg_n = "LogSuccessfulConnections"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##9.3 Public Profile
function _9.3.1.PublicEnableFirewall{
    $stat = 'Fail'
    Write-Host "9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $reg_n = "EnableFirewall"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.3.2.PublicDefaultInboundAction{
    $stat = 'Fail'
    Write-Host "9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $reg_n = "DefaultInboundAction"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.3.3.PublicDefaultOutboundAction{
    $stat = 'Fail'
    Write-Host "9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $reg_n = "DefaultOutboundAction"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.3.4.PublicDisableNotifications{
    $stat = 'Fail'
    Write-Host "9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $reg_n = "DisableNotifications"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.3.5.PublicAllowLocalPolicyMerge{
    $stat = 'Fail'
    Write-Host "9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $reg_n = "PublicAllowLocalPolicyMerge"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.3.6.PublicAllowLocalIPsecPolicyMerge{
    $stat = 'Fail'
    Write-Host "9.3.6 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $reg_n = "PublicAllowLocalIPsecPolicyMerge"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.3.7.PublicLogFilePath{
    $stat = 'Fail'
    Write-Host "9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
    $reg_n = "LogFilePath"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -like "%SystemRoot%\System32\logfiles\firewall\publicfw.log"){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.3.8.PublicLogFileSize{
    $stat = 'Fail'
    Write-Host "9.3.8 (L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
    $reg_n = "LogFileSize"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -ge 16384){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.3.9.PublicLogDroppedPackets{
    $stat = 'Fail'
    Write-Host "9.3.9 (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
    $reg_n = "LogDroppedPackets"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _9.3.10.PublicLogSuccessfulConnections{
    $stat = 'Fail'
    Write-Host "9.3.10 (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
    $reg_n = "LogSuccessfulConnections"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.1.1.AuditCredentialValidation{
    $stat = 'Fail'
    Write-Host "17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
    $sub_c = "Credential Validation"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.1.2.AuditKerberosAuthServiceDC{
    $stat = 'Fail'
    Write-Host "17.1.2 (L1) Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure'"
    $sub_c = "Kerberos Authentication Service"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.1.3.AuditKerbServTicketOperDC{
    $stat = 'Fail'
    Write-Host "17.1.3 (L1) Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'"
    $sub_c = "Kerberos Service Ticket Operations"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.2.1.AuditComputerAccountGroupManagement{
    $stat = 'Fail'
    Write-Host "17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
    $sub_c = "Application Group Management"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.2.2.AuditComputerAccountManagementDC{
    $stat = 'Fail'
    Write-Host "17.2.2 (L1) Ensure 'Audit Computer Account Management' is set to include 'Success'"
    $sub_c = "Computer Account Management"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.2.3.AuditDistribGroupManagementDC{
    $stat = 'Fail'
    Write-Host "17.2.3 (L1) Ensure 'Audit Distribution Group Management' is set to include 'Success'"
    $sub_c = "Distribution Group Management"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.2.4.AuditOtherAccountManagementEventsDC{
    $stat = 'Fail'
    Write-Host "17.2.4 (L1) Ensure 'Audit Other Account Management Events' is set to include 'Success'"
    $sub_c = "Other Account Management Events"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.2.5.AuditSecurityGroupManagement{
    $stat = 'Fail'
    Write-Host "17.2.5 (L1) Ensure 'Audit Security Group Management' is set to include 'Success'"
    $sub_c = "Security Group Management"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.2.6.AuditSecurityGroupManagement{
    $stat = 'Fail'
    Write-Host "17.2.6 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'"
    $sub_c = "User Account Management"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##17.3 Detailed Tracking
function _17.3.1.AuditPNPActivity{
    $stat = 'Fail'
    Write-Host "17.3.1 (L1) Ensure 'Audit PNP Activity' is set to include 'Success'"
    $sub_c = "Plug and Play Events"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.3.2.AuditProcessCreation{
    $stat = 'Fail'
    Write-Host "17.3.2 (L1) Ensure 'Audit Process Creation' is set to include 'Success'"
    $sub_c = "Process Creation"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##17.4 DS Access
function _17.4.1.AuditDirectoryServiceAccessDC{
    $stat = 'Fail'
    Write-Host "17.4.1 (L1) Ensure 'Audit Directory Service Access' is set to include 'Failure'"
    $sub_c = "Directory Service Access"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.4.2.AuditDirectoryServiceChangesDC{
    $stat = 'Fail'
    Write-Host "17.4.2 (L1) Ensure 'Audit Directory Service Changes' is set to include 'Success'"
    $sub_c = "Directory Service Changes"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##17.5 Logon/Logoff
function _17.5.1.AuditAccountLockout{
    $stat = 'Fail'
    Write-Host "17.5.1 (L1) Ensure 'Audit Account Lockout' is set to include 'Failure'"
    $sub_c = "Account Lockout"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.5.2.AuditGroupMembership{
    $stat = 'Fail'
    Write-Host "17.5.2 (L1) Ensure 'Audit Group Membership' is set to include 'Success'"
    $sub_c = "Group Membership"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.5.3.AuditLogoff{
    $stat = 'Fail'
    Write-Host "17.5.3 (L1) Ensure 'Audit Logoff' is set to include 'Success'"
    $sub_c = "Logoff"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.5.4.AuditLogon{
    $stat = 'Fail'
    Write-Host "17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'"
    $sub_c = "Logon"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.5.5.AuditOtherLogonLogoffEvents{
    $stat = 'Fail'
    Write-Host "17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
    $sub_c = "Other Logon/Logoff Events"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.5.6.AuditSpecialLogon{
    $stat = 'Fail'
    Write-Host "17.5.6 (L1) Ensure 'Audit Special Logon' is set to include 'Success'"
    $sub_c = "Special Logon"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##17.6 Object Access
function _17.6.1.AuditDetailedFileShare{
    $stat = 'Fail'
    Write-Host "17.6.1 (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'"
    $sub_c = "Detailed File Share"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.6.2.AuditFileShare{
    $stat = 'Fail'
    Write-Host "17.6.2 (L1) Ensure 'Audit File Share' is set to 'Success and Failure'"
    $sub_c = "File Share"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.6.3.AuditOtherObjectAccessEvents{
    $stat = 'Fail'
    Write-Host "17.6.3 (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"
    $sub_c = "Other Object Access Events"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.6.4.AuditRemovableStorage{
    $stat = 'Fail'
    Write-Host "17.6.4 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
    $sub_c = "Removable Storage"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##17.7 Policy Change
function _17.7.1.AuditPolicyChange{
    $stat = 'Fail'
    Write-Host "17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to include 'Success'"
    $sub_c = "Audit Policy Change"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.7.2.AuditAuthenticationPolicyChange{
    $stat = 'Fail'
    Write-Host "17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to include 'Success'"
    $sub_c = "Authentication Policy Change"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.7.3.AuditAuthorizationPolicyChange{
    $stat = 'Fail'
    Write-Host "17.7.3 (L1) Ensure 'Audit Authorization Policy Change' is set to include 'Success'"
    $sub_c = "Authorization Policy Change"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.7.4.AuditMPSSVCRuleLevelPolicyChange{
    $stat = 'Fail'
    Write-Host "17.7.4 (L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"
    $sub_c = "MPSSVC Rule-Level Policy Change"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.7.5.AuditOtherPolicyChangeEvents{
    $stat = 'Fail'
    Write-Host "17.7.5 (L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure'"
    $sub_c = "Other Policy Change Events"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##17.8 Privilege Use
function _17.8.1.AuditSpecialLogon{
    $stat = 'Fail'
    Write-Host "17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"
    $sub_c = "Sensitive Privilege Use"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##17.9 System
function _17.9.1.AuditIPsecDriver{
    $stat = 'Fail'
    Write-Host "17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"
    $sub_c = "IPsec Driver"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.9.2.AuditOtherSystemEvents{
    $stat = 'Fail'
    Write-Host "17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'"
    $sub_c = "Other System Events"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.9.3.AuditSecurityStateChange{
    $stat = 'Fail'
    Write-Host "17.9.3 (L1) Ensure 'Audit Security State Change' is set to include 'Success'"
    $sub_c = "Security State Change"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.9.4.AuditSecuritySystemExtension{
    $stat = 'Fail'
    Write-Host "17.9.4 (L1) Ensure 'Audit Security System Extension' is set to include 'Success'"
    $sub_c = "Security System Extension"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _17.9.5.AuditSystemIntegrity{
    $stat = 'Fail'
    Write-Host "17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'"
    $sub_c = "System Integrity"
    $val = Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c
    Write-Host "Command:  Auditpol /get /subcategory:$sub_c | Select-String -SimpleMatch $sub_c"
    Write-Host "Command result: "$val
    $val  -match '\s\s\s.+\w*$' | Out-Null
    $clearsp = $Matches.0
    $clearsp -match '\w.+$' | Out-Null
    If($Matches.0 -like "Success and Failure"){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18 Administrative Templates (Computer)
##18.1 Control Panel
##18.1.1 Personalization
function _18.1.1.1.PreventEnablingLockScreenCamera{
    $stat = 'Fail'
    Write-Host "18.1.1.1 (L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $reg_n = "NoLockScreenCamera"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.1.1.2.PreventEnablingLockScreenSlideShow{
    $stat = 'Fail'
    Write-Host "18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $reg_n = "NoLockScreenSlideshow"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.1.1.2.PreventEnablingLockScreenSlideShow{
    $stat = 'Fail'
    Write-Host "18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $reg_n = "NoLockScreenSlideshow"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.1.2 Regional and Language Options
##18.1.2.1 Handwriting personalization
function _18.1.2.2.PreventEnablingLockScreenSlideShow{
    $stat = 'Fail'
    Write-Host "18.1.2.2 (L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
    $reg_n = "AllowInputPersonalization"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.1.3.DisallowOnlineTips{
    $stat = 'Fail'
    Write-Host "18.1.3 (L2) Ensure 'Allow Online Tips' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $reg_n = "AllowOnlineTips"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.2 LAPS
#Server Member
function _18.2.1_18.2.6.LAPS{
    $stat = 'Pass'
    Write-Host "18.2.1 (L1) Ensure LAPS AdmPwd GPO Extension / CSE is installed"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}"
    $reg_n = "DllName"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    If($val)
    {
        Write-Host "Command result: LAPS AdmPwd GPO Extension / CSE is installed ";
        Write-Host "================================================="
        $stat
        Write-Host "================================================="
        _18.2.2.PwdExpirationProtectionEnabled
        _18.2.3.AdmPwdEnabled 
        _18.2.4.PasswordComplexity
        _18.2.5.PasswordLength
        _18.2.6.PasswordAgeDays
        
    }
    Else
    {
        Write-Host "Command result: Not instaled"
        Write-Host "================================================="
        $stat
        Write-Host "================================================="
    } 
}
function _18.2.2.PwdExpirationProtectionEnabled{
    $stat = 'Fail'
    Write-Host "18.2.2 (L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $reg_n = "PwdExpirationProtectionEnabled"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.2.3.AdmPwdEnabled{
    $stat = 'Fail'
    Write-Host "8.2.3 (L1) Ensure 'Enable Local Admin Password Management' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $reg_n = "AdmPwdEnabled"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.2.4.PasswordComplexity{
    $stat = 'Fail'
    Write-Host "18.2.4 (L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $reg_n = "PasswordComplexity"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.2.5.PasswordLength{
    $stat = 'Fail'
    Write-Host "18.2.5 (L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $reg_n = "PasswordLength"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -ge 15){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.2.6.PasswordAgeDays{
    $stat = 'Fail'
    Write-Host "18.2.6 (L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $reg_n = "PasswordAgeDays"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -le 30){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.3 MS Security Guide
function _18.3.1.LocalAccountTokenFilterPolicy{
    $stat = 'Fail'
    Write-Host "18.3.1 (L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $reg_n = "LocalAccountTokenFilterPolicy"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.3.2.ConfigureSMBv1ClientDriver{
    $stat = 'Fail'
    Write-Host "18.3.2 (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb1"
    $reg_n = "Start"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.3.3.ConfigureSMBv1server{
    $stat = 'Fail'
    Write-Host "18.3.3 (L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $reg_n = "SMB1"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.3.4.DisableExceptionChainValidation{
    $stat = 'Fail'
    Write-Host "18.3.4 (L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
    $reg_n = "DisableExceptionChainValidation"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.3.5.LdapEnforceChannelBindingDC{
    $stat = 'Fail'
    Write-Host "18.3.5 (L1) Ensure 'Extended Protection for LDAP Authentication (Domain Controllers only)' is set to 'Enabled: Enabled, always (recommended)'"
    $reg_p = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $reg_n = "LdapEnforceChannelBinding"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.3.6.NetBIOSNodeType{
    $stat = 'Fail'
    Write-Host "18.3.6 (L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    $reg_n = "NodeType"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 2){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.3.7.WDigestUseLogonCredential{
    $stat = 'Fail'
    Write-Host "18.3.7 (L1) Ensure 'WDigest Authentication' is set to 'Disabled'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $reg_n = "UseLogonCredential"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.4 MSS (Legacy)
function _18.4.1.WinlogonAutoAdminLogon{
    $stat = 'Fail'
    Write-Host "18.4.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $reg_n = "AutoAdminLogon"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.4.2.DisableIPv6SourceRouting{
    $stat = 'Fail'
    Write-Host "18.4.2 (L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $reg_n = "DisableIPSourceRouting"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.4.3.DisableIPv4SourceRouting{
    $stat = 'Fail'
    Write-Host "18.4.3 (L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $reg_n = "DisableIPSourceRouting"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.4.4.EnableICMPRedirect{
    $stat = 'Fail'
    Write-Host "18.4.4 (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $reg_n = "EnableICMPRedirect"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.4.5.TcpIpKeepAliveTime{
    $stat = 'Fail'
    Write-Host "18.4.5 (L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $reg_n = "KeepAliveTime"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 300000){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.4.6.NoNameReleaseOnDemand{
    $stat = 'Fail'
    Write-Host "18.4.6 (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    $reg_n = "NoNameReleaseOnDemand"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.4.7.PerformRouterDiscovery{
    $stat = 'Fail'
    Write-Host "18.4.7 (L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $reg_n = "PerformRouterDiscovery"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.4.8.SafeDllSearchMode{
    $stat = 'Fail'
    Write-Host "18.4.8 (L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager"
    $reg_n = "SafeDllSearchMode"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.4.9.ScreenSaverGracePeriod{
    $stat = 'Fail'
    Write-Host "18.4.9 (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $reg_n = "ScreenSaverGracePeriod"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -le 5){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.4.10.TcpMaxDataRetransmissionsV6{
    $stat = 'Fail'
    Write-Host "18.4.10 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
    $reg_n = "TcpMaxDataRetransmissions"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 3){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.4.11.TcpMaxDataRetransmissions{
    $stat = 'Fail'
    Write-Host "18.4.11 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $reg_n = "TcpMaxDataRetransmissions"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 3){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.4.12.SecurityWarningLevel{
    $stat = 'Fail'
    Write-Host "18.4.12 (L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
    $reg_n = "WarningLevel"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -le 90){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.5 Network
##18.5.1 Background Intelligent Transfer Service (BITS)
##18.5.2 BranchCache
##18.5.3 DirectAccess Client Experience Settings
##18.5.4 DNS Client
function _18.5.4.1.EnableMulticast{
    $stat = 'Fail'
    Write-Host "18.5.4.1 (L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $reg_n = "EnableMulticast"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.5.5 Fonts
function _18.5.5.1.EnableFontProviders{
    $stat = 'Fail'
    Write-Host "18.5.5.1 (L2) Ensure 'Enable Font Providers' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $reg_n = "EnableFontProviders"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.5.6 Hotspot Authentication
##18.5.7 Lanman Server
##18.5.8 Lanman Workstation
function _18.5.8.1.AllowInsecureGuestAuth{
    $stat = 'Fail'
    Write-Host "18.5.8.1 (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
    $reg_n = "AllowInsecureGuestAuth"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.5.9 Link-Layer Topology Discovery
function _18.5.9.1.LLTDIODisabled{
    $stat = 'Fail'
    Write-Host "18.5.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    $reg_All = @('AllowLLTDIOOnDomain','AllowLLTDIOOnPublicNet','EnableLLTDIO','ProhibitLLTDIOOnPrivateNet')
    $done = 0
    foreach($reg_n in $reg_All){
        try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
        Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
        If($val -notlike ""){
            Write-Host "Command result: "$val; If($val -eq 0){$done += 1}}
        Else{
            Write-Host "Command result: Disabled or Not Configured"}
    }
    If($done -eq 4){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.5.9.2.RSPNDRDisabled{
    $stat = 'Fail'
    Write-Host "18.5.9.2 (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    $reg_All = @('AllowRspndrOnDomain','AllowRspndrOnPublicNet','EnableRspndr','ProhibitRspndrOnPrivateNet')
    $done = 0
    foreach($reg_n in $reg_All){
        try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
        Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
        If($val -notlike ""){
            Write-Host "Command result: "$val; If($val -eq 0){$done += 1}}
        Else{
            Write-Host "Command result: Disabled or Not Configured"}
    }
    If($done -eq 4){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.5.10 Microsoft Peer-to-Peer Networking Services
##18.5.10.1 Peer Name Resolution Protocol
function _18.5.10.2.PeernetDisabled{
    $stat = 'Fail'
    Write-Host "18.5.10.2 (L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
    $reg_n = "Disabled"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.5.11 Network Connections
##18.5.11.1 Windows Defender Firewall (formerly Windows Firewall)
function _18.5.11.2.PeernetDisabled{
    $stat = 'Fail'
    Write-Host "18.5.11.2 (L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    $reg_n = "NC_AllowNetBridge_NLA"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.5.11.3.ProhibitInternetConnectionSharing{
    $stat = 'Fail'
    Write-Host "18.5.11.3 (L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    $reg_n = "NC_ShowSharedAccessUI"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.5.11.4.StdDomainUserSetLocation{
    $stat = 'Fail'
    Write-Host "18.5.11.4 (L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    $reg_n = "NC_StdDomainUserSetLocation"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.5.12 Network Connectivity Status Indicator
##18.5.13 Network Isolation
##18.5.14 Network Provider
function _18.5.14.1.HardenedPaths{
    $stat = 'Fail'
    Write-Host "18.5.14.1 (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with Require Mutual Authentication and Require Integrity set for all NETLOGON and SYSVOL shares'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
    $reg_All = @('\\*\NETLOGON','\\*\SYSVOL')
    $done = 0
    foreach($reg_n in $reg_All){
        try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
        Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
        If($val -notlike ""){
            Write-Host "Command result: "$val; If($val -like "RequireMutualAuthentication=1, RequireIntegrity=1"){$done += 1}}
        Else{
            Write-Host "Command result: Disabled or Not Configured"}
    }
    If($done -eq $reg_All.Length){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.5.15 Offline Files
##18.5.16 QoS Packet Scheduler
##18.5.17 SNMP
##18.5.18 SSL Configuration Settings
##8.5.19 TCPIP Settings
##18.5.19.1 IPv6 Transition Technologies
##18.5.19.2 Parameters
function _18.5.19.2.1.DisableIPv6DisabledComponents{
    $stat = 'Fail'
    Write-Host "18.5.19.2.1 (L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
    $reg_n = "DisabledComponents"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 255){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.5.20 Windows Connect Now
function _18.5.20.1.DisableConfigurationWirelessSettings{
    $stat = 'Fail'
    Write-Host "18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
    $reg_All = @('EnableRegistrars','DisableUPnPRegistrar','DisableInBand802DOT11Registrar','DisableFlashConfigRegistrar','DisableWPDRegistrar')
    $done = 0
    foreach($reg_n in $reg_All){
        try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
        Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
        If($val -notlike ""){
            Write-Host "Command result: "$val; If($val -eq 0){$done += 1}}
        Else{
            Write-Host "Command result: Disabled or Not Configured"}
    }
    If($done -eq $reg_All.Length){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.5.20.2.ProhibitaccessWCNwizards{
    $stat = 'Fail'
    Write-Host "18.5.20.2 (L2) Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
    $reg_n = "DisableWcnUi"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.5.21 Windows Connection Manager
function _18.5.21.1.fMinimizeConnections{
    $stat = 'Fail'
    Write-Host "18.5.21.1 (L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
    $reg_n = "fMinimizeConnections"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 3){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.5.21.2.fBlockNonDomain{
    $stat = 'Fail'
    Write-Host "18.5.21.2 (L2) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
    $reg_n = "fBlockNonDomain"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.6 Printers
##18.7 Start Menu and Taskbar
##18.7.1 Notifications
function _18.7.1.1.NoCloudApplicationNotification{
    $stat = 'Fail'
    Write-Host "18.7.1.1 (L2) Ensure 'Turn off notifications network usage' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    $reg_n = "NoCloudApplicationNotification"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8 System
##18.8.1 Access-Denied Assistance
##18.8.2 App-V
##18.8.3 Audit Process Creation
function _18.8.3.1.ProcessCreationIncludeCmdLine{
    $stat = 'Fail'
    Write-Host "18.8.3.1 (L1) Ensure 'Include command line in process creation events' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $reg_n = "ProcessCreationIncludeCmdLine_Enabled"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.4 Credentials Delegation
function _18.8.4.1.EncryptionOracleRemediation{
    $stat = 'Fail'
    Write-Host "18.8.4.1 (L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
    $reg_n = "AllowEncryptionOracle"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.4.2.AllowProtectedCreds{
    $stat = 'Fail'
    Write-Host "18.8.4.2 (L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
    $reg_n = "AllowProtectedCreds"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.5 Device Guard
function _18.8.5.1.EnableVirtualizationBasedSecurity{
    $stat = 'Fail'
    Write-Host "18.8.5.1 (NG) Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $reg_n = "EnableVirtualizationBasedSecurity"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.5.2.RequirePlatformSecurityFeatures{
    $stat = 'Fail'
    Write-Host "18.8.5.2 (NG) Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $reg_n = "RequirePlatformSecurityFeatures"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 3){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.5.3.HypervisorEnforcedCodeIntegrity{
    $stat = 'Fail'
    Write-Host "18.8.5.3 (NG) Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'" ""
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $reg_n = "HypervisorEnforcedCodeIntegrity"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.5.4.HVCIMATRequired{
    $stat = 'Fail'
    Write-Host "18.8.5.4 (NG) Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $reg_n = "HVCIMATRequired"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.5.5.LsaCfgFlags{
    $stat = 'Fail'
    Write-Host "18.8.5.5 (NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $reg_n = "LsaCfgFlags"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.5.6.LsaCfgFlagDC{
    $stat = 'Fail'
    Write-Host "18.8.5.6 (NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $reg_n = "LsaCfgFlags"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.5.7.ConfigureSystemGuardLaunch{
    $stat = 'Fail'
    Write-Host "18.8.5.7 (NG) Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    $reg_n = "ConfigureSystemGuardLaunch"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.6 Device Health Attestation Service
##18.8.7 Device Installation
##18.8.8 Device Redirection
##18.8.9 Disk NV Cache
##18.8.10 Disk Quotas
##18.8.11 Display
##18.8.12 Distributed COM
##18.8.13 Driver Installation
##18.8.14 Early Launch Antimalware
function _18.8.14.1.DriverLoadPolicy{
    $stat = 'Fail'
    Write-Host "18.8.14.1 (L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
    $reg_p = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
    $reg_n = "DriverLoadPolicy"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.15 Enhanced Storage Access
##18.8.16 File Classification Infrastructure
##18.8.17 File Share Shadow Copy Agent
##18.8.18 File Share Shadow Copy Provider
##18.8.19 Filesystem (formerly NTFS Filesystem)
##18.8.20 Folder Redirection
##18.8.21 Group Policy
##18.8.21.1 Logging and tracing
function _18.8.21.2.NoBackgroundPolicy{
    $stat = 'Fail'
    Write-Host "18.8.21.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
    $reg_n = "NoBackgroundPolicy"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.21.3.NoGPOListChanges{
    $stat = 'Fail'
    Write-Host "18.8.21.3 (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
    $reg_n = "NoGPOListChanges"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.21.4.EnableCdp{
    $stat = 'Fail'
    Write-Host "18.8.21.4 (L1) Ensure 'Continue experiences on this device' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $reg_n = "EnableCdp"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.21.5.DisableBkGndGroupPolicy{
    $stat = 'Fail'
    Write-Host "18.8.21.5 (L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $reg_n = "DisableBkGndGroupPolicy"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.22 Internet Communication Management
##18.8.22.1 Internet Communication settings
function _18.8.22.1.1.DisableWebPnPDownload{
    $stat = 'Fail'
    Write-Host "18.8.22.1.1 (L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $reg_n = "DisableWebPnPDownload"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.22.1.2.PreventHandwritingDataSharing{
    $stat = 'Fail'
    Write-Host "18.8.22.1.2 (L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"
    $reg_n = "PreventHandwritingDataSharing"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.22.1.3.PreventHandwritingErrorReports{
    $stat = 'Fail'
    Write-Host "18.8.22.1.3 (L2) Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
    $reg_n = "PreventHandwritingErrorReports"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.22.1.4.ExitOnMSICW{
    $stat = 'Fail'
    Write-Host "18.8.22.1.4 (L2) Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard"
    $reg_n = "ExitOnMSICW"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.22.1.5.NoWebServices{
    $stat = 'Fail'
    Write-Host "18.8.22.1.5 (L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $reg_n = "NoWebServices"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.22.1.6.DisableHTTPPrinting{
    $stat = 'Fail'
    Write-Host "18.8.22.1.6 (L2) Ensure 'Turn off printing over HTTP' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $reg_n = "DisableHTTPPrinting"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.22.1.7.NoRegistration{
    $stat = 'Fail'
    Write-Host "18.8.22.1.7 (L2) Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control"
    $reg_n = "NoRegistration"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.22.1.8.DisableContentFileUpdates{
    $stat = 'Fail'
    Write-Host "18.8.22.1.8 (L2) Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion"
    $reg_n = "DisableContentFileUpdates"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.22.1.9.NoOnlinePrintsWizard{
    $stat = 'Fail'
    Write-Host "18.8.22.1.9 (L2) Ensure 'Turn off the Order Prints picture task' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $reg_n = "NoOnlinePrintsWizard"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.22.1.10.NoPublishingWizard{
    $stat = 'Fail'
    Write-Host "18.8.22.1.10 (L2) Ensure 'Turn off the Publish to Web task for files and folders' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $reg_n = "NoPublishingWizard"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.22.1.11.CEIP{
    $stat = 'Fail'
    Write-Host "18.8.22.1.11 (L2) Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
    $reg_n = "CEIP"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.22.1.12.CEIPEnable{
    $stat = 'Fail'
    Write-Host "18.8.22.1.12 (L2) Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
    $reg_n = "CEIPEnable"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.22.1.13.TurnoffWindowsErrorReporting{
    $stat = 'Fail'
    Write-Host "18.8.22.1.13 (L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
    $reg_All = @('Disabled','DoReport')
    $done = 0
    foreach($reg_n in $reg_All){
        try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
        Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
        $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting"
        If($val -notlike ""){
            Write-Host "Command result: "$val; If($val -eq 1){$done += 1}
            }
        Else{
            Write-Host "Command result: Disabled or Not Configured"
            }
    }
    If($done -eq $reg_All.Length){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.23 iSCSI
##18.8.24 KDC
##18.8.25 Kerberos
function _18.8.25.1.SupportDeviceAuthenticationUsingCertificate{
    $stat = 'Fail'
    Write-Host "18.8.25.1 (L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
    $reg_All = @('DevicePKInitBehavior','DevicePKInitEnabled')
    $done = 0
    foreach($reg_n in $reg_All){
        try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
        Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
        If($val -notlike ""){
            Write-Host "Command result: "$val; If($val -eq 1){$done += 1}
            }
        Else{
            Write-Host "Command result: Disabled or Not Configured"
            }
    }
    If($done -eq $reg_All.Length){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.26 Kernel DMA Protection
function _18.8.26.1.DeviceEnumerationPolicy{
    $stat = 'Fail'
    Write-Host "18.8.26.1 (L1) Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
    $reg_n = "DeviceEnumerationPolicy"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.27 Locale Services
function _18.8.27.1.BlockUserInputMethodsForSignIn{
    $stat = 'Fail'
    Write-Host "18.8.27.1 (L2) Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"
    $reg_n = "BlockUserInputMethodsForSignIn"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.28 Logon
function _18.8.28.1.BlockUserFromShowingAccountDetailsOnSignin{
    $stat = 'Fail'
    Write-Host "18.8.28.1 (L1) Ensure 'Block user from showing account details on signin' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $reg_n = "BlockUserFromShowingAccountDetailsOnSignin"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.28.2.DontDisplayNetworkSelectionUI{
    $stat = 'Fail'
    Write-Host "18.8.28.2 (L1) Ensure 'Do not display network selection UI' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $reg_n = "DontDisplayNetworkSelectionUI"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.28.3.DontEnumerateConnectedUsers{
    $stat = 'Fail'
    Write-Host "18.8.28.3 (L1) Ensure 'Do not enumerate connected users on domainjoined computers' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $reg_n = "DontEnumerateConnectedUsers"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.28.4.EnumerateLocalUsers{
    $stat = 'Fail'
    Write-Host "18.8.28.4 (L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $reg_n = "EnumerateLocalUsers"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.28.5.DisableLockScreenAppNotifications{
    $stat = 'Fail'
    Write-Host "18.8.28.5 (L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $reg_n = "DisableLockScreenAppNotifications"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.28.6.BlockDomainPicturePassword{
    $stat = 'Fail'
    Write-Host "18.8.28.6 (L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $reg_n = "BlockDomainPicturePassword"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.28.7.AllowDomainPINLogon{
    $stat = 'Fail'
    Write-Host "18.8.28.7 (L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $reg_n = "AllowDomainPINLogon"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.29 Mitigation Options
##18.8.30 Net Logon
##18.8.31 OS Policies
function _18.8.31.1.AllowCrossDeviceClipboard{
    $stat = 'Fail'
    Write-Host "18.8.31.1 (L2) Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $reg_n = "AllowCrossDeviceClipboard"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.31.2.UploadUserActivities{
    $stat = 'Fail'
    Write-Host "18.8.31.2 (L2) Ensure 'Allow upload of User Activities' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $reg_n = "UploadUserActivities"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.32 Performance Control Panel
##18.8.33 PIN Complexity
##18.8.34 Power Management
##18.8.34.1 Button Settings
##18.8.34.2 Energy Saver Settings
##18.8.34.3 Hard Disk Settings
##18.8.34.4 Notification Settings
##18.8.32.5 Power Throttling Settings
##18.8.34.6 Sleep Settings
function _18.8.34.6.1.AllowNetworkBatteryStandby{
    $stat = 'Fail'
    Write-Host "18.8.34.6.1 (L2) Ensure 'Allow network connectivity during connectedstandby (on battery)' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e898b7-4186-b944-eafa664402d9"
    $reg_n = "DCSettingIndex"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.34.6.2.AllowNetworkACStandby{
    $stat = 'Fail'
    Write-Host "18.8.34.6.2 (L2) Ensure 'Allow network connectivity during connectedstandby (plugged in)' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e898b7-4186-b944-eafa664402d9"
    $reg_n = "ACSettingIndex"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.34.6.3.RequirePasswordWakes{
    $stat = 'Fail'
    Write-Host "18.8.34.6.3 (L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51"
    $reg_n = "DCSettingIndex"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.34.6.4.RequirePasswordWakesAC{
    $stat = 'Fail'
    Write-Host "18.8.34.6.4 (L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51"
    $reg_n = "ACSettingIndex"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.35 Recovery
##18.8.36 Remote Assistance
function _18.8.36.1.fAllowUnsolicited{
    $stat = 'Fail'
    Write-Host "18.8.36.1 (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "fAllowUnsolicited"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.36.2.fAllowToGetHelp{
    $stat = 'Fail'
    Write-Host "18.8.36.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "fAllowToGetHelp"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.37 Remote Procedure Call
function _18.8.37.1.EnableAuthEpResolution{
    $stat = 'Fail'
    Write-Host "18.8.37.1 (L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
    $reg_n = "EnableAuthEpResolution"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.37.2.RestrictRemoteClients{
    $stat = 'Fail'
    Write-Host "18.8.37.2 (L2) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
    $reg_n = "RestrictRemoteClients"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.38 Removable Storage Access
##18.8.39 Scripts
##18.8.40 Server Manager
##18.8.41 Shutdown
##18.8.42 Shutdown Options
##18.8.43 Storage Health
##18.8.44 System Restore
##18.8.45 Troubleshooting and Diagnostics
##18.8.45.2 Application Compatibility Diagnostics
##18.8.45.1 Corrupted File Recovery
##18.8.45.3 Disk Diagnostic
##18.8.45.4 Fault Tolerant Heap
##18.8.45.5 Microsoft Support Diagnostic Tool
function _18.8.45.5.1.DisableQueryRemoteServer{
    $stat = 'Fail'
    Write-Host "18.8.45.5.1 (L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy"
    $reg_n = "DisableQueryRemoteServer"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.45.6 MSI Corrupted File Recovery
##18.8.45.7 Scheduled Maintenance
##18.8.45.9 Scripted Diagnostics
##18.8.45.8 Windows Boot Performance Diagnostics
##18.8.45.10 Windows Memory Leak Diagnosis
##18.8.45.11 Windows Performance PerfTrack
function _18.8.45.11.1.ScenarioExecutionEnabled{
    $stat = 'Fail'
    Write-Host "18.8.45.11.1 (L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b9654fc3-8781-88dd50a6299d}"
    $reg_n = "ScenarioExecutionEnabled"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.46 Trusted Platform Module Services
##18.8.47 User Profiles
function _18.8.47.1.DisabledAdvertisingInfo{
    $stat = 'Fail'
    Write-Host "18.8.47.1 (L2) Ensure 'Turn off the advertising ID' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    $reg_n = "DisabledByGroupPolicy"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.8.48 Windows File Protection
##18.8.49 Windows HotStart
##18.8.50 Windows Time Service
##18.8.50.1 Time Providers
function _18.8.50.1.1.NtpClientEnabled{
    $stat = 'Fail'
    Write-Host "18.8.50.1.1 (L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
    $reg_n = "Enabled"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.8.50.1.2.DisableWindowsNTPServer{
    $stat = 'Fail'
    Write-Host "18.8.50.1.2 (L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer"
    $reg_n = "Enabled"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9 Windows Components
##18.9.1 Active Directory Federation Services
##18.9.2 ActiveX Installer Service
##18.9.3 Add features to Windows 8 / 8.1 / 10 (formerly Windows Anytime Upgrade)
##18.9.4 App Package Deployment
function _18.9.4.AllowSharedLocalAppData{
    $stat = 'Fail'
    Write-Host "18.9.4.1 (L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager"
    $reg_n = "AllowSharedLocalAppData"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.5 App Privacy
##18.9.6 App runtime
function _18.9.6.1.MSAOptional{
    $stat = 'Fail'
    Write-Host "18.9.6.1 (L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $reg_n = "MSAOptional"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.7 Application Compatibility
##18.9.8 AutoPlay Policies
function _18.9.8.1.NoAutoplayfornonVolume{
    $stat = 'Fail'
    Write-Host "18.9.8.1 (L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    $reg_n = "NoAutoplayfornonVolume"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.8.2.NoAutorun{
    $stat = 'Fail'
    Write-Host "18.9.8.2 (L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $reg_n = "NoAutorun"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.8.3.NoDriveTypeAutoRun{
    $stat = 'Fail'
    Write-Host "18.9.8.3 (L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $reg_n = "NoDriveTypeAutoRun"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.9 Backup
##18.9.10 Biometrics
##18.9.10.1 Facial Features
function _18.9.10.1.1.EnhancedAntiSpoofing{
    $stat = 'Fail'
    Write-Host "18.9.10.1.1 (L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
    $reg_n = "EnhancedAntiSpoofing"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.11 BitLocker Drive Encryption
##18.9.12 Camera
function _18.9.12.1.DisallowCamera{
    $stat = 'Fail'
    Write-Host "18.9.12.1 (L2) Ensure 'Allow Use of Camera' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Camera"
    $reg_n = "AllowCamera"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.13 Cloud Content
function _18.9.13.1.DisableWindowsConsumerFeatures{
    $stat = 'Fail'
    Write-Host "18.9.13.1 (L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $reg_n = "DisableWindowsConsumerFeatures"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.14 Connect
function _18.9.14.1.RequirePinForPairing{
    $stat = 'Fail'
    Write-Host "18.9.14.1 (L1) Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
    $reg_n = "RequirePinForPairing"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.15 Credential User Interface
function _18.9.15.1.DisablePasswordReveal{
    $stat = 'Fail'
    Write-Host "18.9.15.1 (L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"
    $reg_n = "DisablePasswordReveal"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.15.2.DisableEnumerateAdministrators{
    $stat = 'Fail'
    Write-Host "18.9.15.2 (L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
    $reg_n = "EnumerateAdministrators"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.16 Data Collection and Preview Builds
function _18.9.16.1.DisallowTelemetry{
    $stat = 'Fail'
    Write-Host "18.9.16.1 (L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $reg_n = "AllowTelemetry"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.16.2.DisableEnterpriseAuthProxy{
    $stat = 'Fail'
    Write-Host "18.9.16.2 (L2) Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $reg_n = "DisableEnterpriseAuthProxy"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.16.3.DoNotShowFeedbackNotifications{
    $stat = 'Fail'
    Write-Host "18.9.16.3 (L1) Ensure 'Do not show feedback notifications' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $reg_n = "DoNotShowFeedbackNotifications"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.16.4.AllowBuildPreview{
    $stat = 'Fail'
    Write-Host "18.9.16.4 (L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
    $reg_n = "AllowBuildPreview"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.17 Delivery Optimization
##18.9.18 Desktop Gadgets
##18.9.19 Desktop Window Manager
##18.9.20 Device and Driver Compatibility
##18.9.21 Device Registration (formerly Workplace Join)
##18.9.22 Digital Locker
##18.9.23 Edge UI
##18.9.24 EMET
##18.9.25 Event Forwarding
##18.9.26 Event Log Service
##18.9.26.1 Application
function _18.9.26.1.1.EventLogRetention{
    $stat = 'Fail'
    Write-Host "18.9.26.1.1 (L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
    $reg_n = "Retention"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.26.1.2.EventLogMaxSize{
    $stat = 'Fail'
    Write-Host "18.9.26.1.2 (L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
    $reg_n = "MaxSize"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -ge 32768){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.26.2 Security
function _18.9.26.2.1.EventLogSecurityRetention{
    $stat = 'Fail'
    Write-Host "18.9.26.2.1 (L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
    $reg_n = "Retention"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.26.2.2.EventLogSecurityMaxSize{
    $stat = 'Fail'
    Write-Host "18.9.26.2.2 (L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
    $reg_n = "MaxSize"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -ge 196608){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.26.3 Setup
function _18.9.26.3.1.EventLogSetupRetention{
    $stat = 'Fail'
    Write-Host "18.9.26.3.1 (L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
    $reg_n = "Retention"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.26.3.2.EventLogSetupMaxSize{
    $stat = 'Fail'
    Write-Host "18.9.26.3.2 (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
    $reg_n = "MaxSize"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -ge 32768){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.26.4 System
function _18.9.26.4.1.EventLogSystemRetention{
    $stat = 'Fail'
    Write-Host "18.9.26.4.1 (L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
    $reg_n = "Retention"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.26.4.2.EventLogSystemMaxSize{
    $stat = 'Fail'
    Write-Host "18.9.26.4.2 (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
    $reg_n = "MaxSize"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -ge 32768){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.27 Event Logging
##18.9.28 Event Viewer
##18.9.29 Family Safety (formerly Parental Controls)
##18.9.30 File Explorer (formerly Windows Explorer)
##18.9.30.1 Previous Versions
function _18.9.30.2.NoDataExecutionPrevention{
    $stat = 'Fail'
    Write-Host "18.9.30.2 (L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    $reg_n = "NoDataExecutionPrevention"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.30.3.NoHeapTerminationOnCorruption{
    $stat = 'Fail'
    Write-Host "18.9.30.3 (L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    $reg_n = "NoHeapTerminationOnCorruption"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.30.4.PreXPSP2ShellProtocolBehavior{
    $stat = 'Fail'
    Write-Host "18.9.30.4 (L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $reg_n = "PreXPSP2ShellProtocolBehavior"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.31 File History
##18.9.32 Find My Device
##18.9.33 Game Explorer
##18.9.34 Handwriting
##18.9.35 HomeGroup
##18.9.36 Import Video
##18.9.37 Internet Explorer
##18.9.38 Internet Information Services
##18.9.39 Location and Sensors
##18.9.39.1 Windows Location Provider
function _18.9.39.2.LocationAndSensorsDisableLocation{
    $stat = 'Fail'
    Write-Host "18.9.39.2 (L2) Ensure 'Turn off location' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    $reg_n = "DisableLocation"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.40 Maintenance Scheduler
##18.9.41 Maps
##18.9.42 MDM
##18.9.43 Messaging
function _18.9.43.1.MessagingAllowMessageSync{
    $stat = 'Fail'
    Write-Host "18.9.43.1 (L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"
    $reg_n = "AllowMessageSync"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.44 Microsoft account
function _18.9.44.1.MicrosoftAccountDisableUserAuth{
    $stat = 'Fail'
    Write-Host "18.9.44.1 (L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
    $reg_n = "DisableUserAuth"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.45 Microsoft Edge
##18.9.46 Microsoft FIDO Authentication
##18.9.47 Microsoft Secondary Authentication Factor
##18.9.48 Microsoft User Experience Virtualization
##18.9.49 NetMeeting
##18.9.50 Network Access Protection
##18.9.51 Network Projector
##18.9.52 OneDrive (formerly SkyDrive)
function _18.9.52.1.OneDriveDisableFileSyncNGSC{
    $stat = 'Fail'
    Write-Host "18.9.52.1 (L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
    $reg_n = "DisableFileSyncNGSC"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.53 Online Assistance
##18.9.54 OOBE
##18.9.55 Password Synchronization
##18.9.56 Portable Operating System
##18.9.57 Presentation Settings
##18.9.58 Push To Install
##8.9.59 Remote Desktop Services (formerly Terminal Services)
##18.9.59.1 RD Licensing (formerly TS Licensing)
##18.9.59.2 Remote Desktop Connection Client
##18.9.59.2.1 RemoteFX USB Device Redirection
function _18.9.59.2.2.TerminalServicesDisablePasswordSaving{
    $stat = 'Fail'
    Write-Host "18.9.59.2.2 (L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "DisablePasswordSaving"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.59.3 Remote Desktop Session Host (formerly Terminal Server)
##18.9.59.3.1 Application Compatibility
##18.9.59.3.2 Connections
function _18.9.59.3.2.TerminalServicesDisablePasswordSaving{
    $stat = 'Fail'
    Write-Host "18.9.59.2.2 (L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "DisablePasswordSaving"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.59.3 Remote Desktop Session Host (formerly Terminal Server)
##18.9.59.3.1 Application Compatibility
##18.9.59.3.2 Connections
function _18.9.59.3.2.1.fSingleSessionPerUser{
    $stat = 'Fail'
    Write-Host "18.9.59.3.2.1 (L2) Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "fSingleSessionPerUser"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.59.3.3 Device and Resource Redirection
function _18.9.59.3.3.1.TerminalServicesfDisableCcm{
    $stat = 'Fail'
    Write-Host "18.9.59.3.3.1 (L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "fDisableCcm"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.59.3.3.2.TerminalServicesfDisableCdm{
    $stat = 'Fail'
    Write-Host "18.9.59.3.3.2 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "fDisableCdm"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.59.3.3.3.TerminalServicesfDisableLPT{
    $stat = 'Fail'
    Write-Host "18.9.59.3.3.3 (L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "fDisableLPT"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.59.3.3.4.TerminalServicesfDisablePNPRedir{
    $stat = 'Fail'
    Write-Host "18.9.59.3.3.4 (L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "fDisablePNPRedir"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.59.3.4 Licensing
##18.9.59.3.5 Printer Redirection
##18.9.59.3.6 Profiles
##18.9.59.3.7 RD Connection Broker (formerly TS Connection Broker)
##18.9.59.3.8 Remote Session Environment
##18.9.59.3.9 Security
function _18.9.59.3.9.1.TerminalServicesfPromptForPassword{
    $stat = 'Fail'
    Write-Host "18.9.59.3.9.1 (L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "fPromptForPassword"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.59.3.9.2.TerminalServicesfEncryptRPCTraffic{
    $stat = 'Fail'
    Write-Host "18.9.59.3.9.2 (L1) Ensure 'Require secure RPC communication' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "fEncryptRPCTraffic"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.59.3.9.3.TerminalServicesSecurityLayer{
    $stat = 'Fail'
    Write-Host "18.9.59.3.9.3 (L1) Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "SecurityLayer"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.59.3.9.4.TerminalServicesUserAuthentication{
    $stat = 'Fail'
    Write-Host "18.9.59.3.9.4 (L1) Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "UserAuthentication"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.59.3.9.5.TerminalServicesMinEncryptionLevel{
    $stat = 'Fail'
    Write-Host "18.9.59.3.9.5 (L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "MinEncryptionLevel"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.59.3.10 Session Time Limits
function _18.9.59.3.10.1.TerminalServicesMaxIdleTime{
    $stat = 'Fail'
    Write-Host "18.9.59.3.10.1 (L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "MaxIdleTime"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -le 15){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.59.3.10.2.TerminalServicesMaxDisconnectionTime{
    $stat = 'Fail'
    Write-Host "18.9.59.3.10.2 (L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "MaxDisconnectionTime"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.59.3.11 Temporary folders
function _18.9.59.3.11.1.TerminalServicesDeleteTempDirsOnExit{
    $stat = 'Fail'
    Write-Host "18.9.59.3.11.1 (L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "DeleteTempDirsOnExit"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.59.3.11.2.TerminalServicesPerSessionTempDir{
    $stat = 'Fail'
    Write-Host "18.9.59.3.11.2 (L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $reg_n = "PerSessionTempDir"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
##18.9.60 RSS Feeds
function _18.9.60.1.DisableEnclosureDownload{
    $stat = 'Fail'
    Write-Host "18.9.60.1 (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
    $reg_n = "DisableEnclosureDownload"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.61 Search
#18.9.61.1 OCR
function _18.9.61.2.WindowsSearchAllowCloudSearch{
    $stat = 'Fail'
    Write-Host "18.9.61.2 (L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    $reg_n = "AllowCloudSearch"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.61.3.AllowIndexingEncryptedStoresOrItems{
    $stat = 'Fail'
    Write-Host "18.9.61.3 (L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    $reg_n = "AllowIndexingEncryptedStoresOrItems"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.62 Security Center
#18.9.63 Server for NIS
#18.9.64 Shutdown Options
#18.9.65 Smart Card
#18.9.66 Software Protection Platform
function _18.9.66.1.NoGenTicket{
    $stat = 'Fail'
    Write-Host "18.9.66.1 (L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
    $reg_n = "NoGenTicket"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.67 Sound Recorder
#18.9.68 Speech
#18.9.69 Store
#18.9.70 Sync your settings
#18.9.71 Tablet PC
#18.9.72 Task Scheduler
#18.9.73 Text Input
#18.9.74 Windows Calendar
#18.9.75 Windows Color System
#18.9.76 Windows Customer Experience Improvement Program
#18.9.77 Windows Defender Antivirus (formerly Windows Defender)
#18.9.77.1 Client Interface
#18.9.77.2 Exclusions
#18.9.77.3 MAPS
function _18.9.77.3.1.LocalSettingOverrideSpynetReporting{
    $stat = 'Fail'
    Write-Host "18.9.77.3.1 (L1) Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
    $reg_n = "LocalSettingOverrideSpynetReporting"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.77.3.2.SpynetReporting{
    $stat = 'Fail'
    Write-Host "18.9.77.3.2 (L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
    $reg_n = "SpynetReporting"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.77.4 MpEngine
#18.9.77.5 Network Inspection System
#18.9.77.6 Quarantine
#18.9.77.7 Real-time Protection
function _18.9.77.7.1.DisableBehaviorMonitoring{
    $stat = 'Fail'
    Write-Host "18.9.77.7.1 (L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled'"
    $reg_p = "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    $reg_n = "DisableBehaviorMonitoring"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.77.8 Remediation
#18.9.77.9 Reporting
function _18.9.77.9.1.DisableGenericRePorts{
    $stat = 'Fail'
    Write-Host "18.9.77.9.1 (L2) Ensure 'Configure Watson events' is set to 'Disabled'"
    $reg_p = "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
    $reg_n = "DisableGenericRePorts"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.77.10 Scan
function _18.9.77.10.1.DisableRemovableDriveScanning{
    $stat = 'Fail'
    Write-Host "18.9.77.10.1 (L1) Ensure 'Scan removable drives' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
    $reg_n = "DisableRemovableDriveScanning"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.77.10.2.DisableEmailScanning{
    $stat = 'Fail'
    Write-Host "18.9.77.10.2 (L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
    $reg_n = "DisableEmailScanning"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.77.11 Signature Updates
#18.9.77.12 Threats
#18.9.77.13 Windows Defender Exploit Guard
#18.9.77.13.1 Attack Surface Reduction
function _18.9.77.13.1.1.ExploitGuard_ASR_Rules{
    $stat = 'Fail'
    Write-Host "18.9.77.13.1.1 (L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
    $reg_n = "ExploitGuard_ASR_Rules"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.77.13.1.2.ConfigureASRrules{
    $stat = 'Fail'
    Write-Host "18.9.77.13.1.2 (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
    $reg_All = @('26190899-1602-49e8-8b27-eb1d0a1ce869','3b576869-a4ec-4529-8536-b80a7769e899','5beb7efe-fd9a-4556-801d-275e5ffc04cc','75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84','7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c','92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b','9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2','b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4','be9ba2d9-53ea-4cdc-84e5-9b1eeee46550','d3e037e1-3eb8-44c8-a917-57927947596d','d4f940ab-401b-4efc-aadc-ad5f3c50688a')
    $done = 0
    foreach($reg_n in $reg_All){
        try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
        Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
        If($val -notlike ""){
            Write-Host "Command result: "$val; If($val -eq 1){$done += 1}}
        Else{
            Write-Host "Command result: Disabled or Not Configured"}
    }
    If($done -eq $reg_All.Length){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.77.13.2 Controlled Folder Access
#18.9.77.13.3 Network Protection
function _18.9.77.13.3.1.EnableNetworkProtection{
    $stat = 'Fail'
    Write-Host "18.9.77.13.3.1 (L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
    $reg_n = "EnableNetworkProtection"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.77.14.PUAProtection{
    $stat = 'Fail'
    Write-Host "18.9.77.14 (L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    $reg_n = "PUAProtection"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.77.15.DisableAntiSpyware{
    $stat = 'Fail'
    Write-Host "18.9.77.15 (L1) Ensure 'Turn off Windows Defender AntiVirus' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    $reg_n = "DisableAntiSpyware"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.78 Windows Defender Application Guard
#18.9.79 Windows Defender Exploit Guard
#18.9.80 Windows Defender SmartScreen
#18.9.80.1 Explorer
function _18.9.80.1.1.DefenderSmartScreen{
    $stat = 'Fail'
    Write-Host "18.9.80.1.1 (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $reg_All = @('EnableSmartScreen','ShellSmartScreenLevel')
    $done = 0
    foreach($reg_n in $reg_All){
        try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
        Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
        If($val -notlike ""){
            Write-Host "Command result: "$val; If($val -eq 1){$done += 1}}
        Else{
            Write-Host "Command result: Disabled or Not Configured"}
    }
    If($done -eq $reg_All.Length){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.81 Windows Error Reporting
#18.9.82 Windows Game Recording and Broadcasting
#18.9.83 Windows Hello for Business (formerly Microsoft Passport for Work)
#18.9.84 Windows Ink Workspace
function _18.9.84.1.AllowSuggestedAppsInWindowsInkWorkspace{
    $stat = 'Fail'
    Write-Host "18.9.84.1 (L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
    $reg_n = "AllowSuggestedAppsInWindowsInkWorkspace"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.84.2.AllowWindowsInkWorkspace{
    $stat = 'Fail'
    Write-Host "18.9.84.2 (L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
    $reg_n = "AllowWindowsInkWorkspace"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.85 Windows Installer
function _18.9.85.1.InstallerEnableUserControl{
    $stat = 'Fail'
    Write-Host "18.9.85.1 (L1) Ensure 'Allow user control over installs' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $reg_n = "EnableUserControl"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.85.2.InstallerAlwaysInstallElevated{
    $stat = 'Fail'
    Write-Host "18.9.85.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $reg_n = "AlwaysInstallElevated"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.85.3.InstallerSafeForScripting{
    $stat = 'Fail'
    Write-Host "18.9.85.3 (L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $reg_n = "SafeForScripting"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.86 Windows Logon Options
function _18.9.86.1.DisableAutomaticRestartSignOn{
    $stat = 'Fail'
    Write-Host "18.9.86.1 (L1) Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $reg_n = "DisableAutomaticRestartSignOn"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.87 Windows Mail
#18.9.88 Windows Media Center
#18.9.89 Windows Media Digital Rights Management
#18.9.90 Windows Media Player
#18.9.91 Windows Meeting Space
#18.9.92 Windows Messenger
#18.9.93 Windows Mobility Center
#18.9.94 Windows Movie Maker
#18.9.95 Windows PowerShell
function _18.9.95.1.EnableScriptBlockLogging{
    $stat = 'Fail'
    Write-Host "18.9.95.1 (L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $reg_n = "EnableScriptBlockLogging"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.95.2.EnableTranscripting{
    $stat = 'Fail'
    Write-Host "18.9.95.2 (L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $reg_n = "EnableTranscripting"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.96 Windows Reliability Analysis
#18.9.97 Windows Remote Management (WinRM)
#18.9.97.1 WinRM Client
function _18.9.97.1.1.WinRMClientAllowBasic{
    $stat = 'Fail'
    Write-Host "18.9.97.1.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
    $reg_n = "AllowBasic"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.97.1.2.WinRMClientAllowUnencryptedTraffic{
    $stat = 'Fail'
    Write-Host "18.9.97.1.2 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
    $reg_n = "AllowUnencryptedTraffic"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.97.1.3.WinRMClientAllowDigest{
    $stat = 'Fail'
    Write-Host "18.9.97.1.3 (L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
    $reg_n = "AllowDigest"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.97.2 WinRM Service
function _18.9.97.2.1.WinRMServiceAllowBasic{
    $stat = 'Fail'
    Write-Host "18.9.97.2.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    $reg_n = "AllowBasic"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.97.2.2.WinRMServiceAllowAutoConfig{
    $stat = 'Fail'
    Write-Host "18.9.97.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    $reg_n = "AllowAutoConfig"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.97.2.3.WinRMServiceAllowUnencryptedTraffic{
    $stat = 'Fail'
    Write-Host "18.9.97.2.3 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    $reg_n = "AllowUnencryptedTraffic"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.97.2.4.WinRMServiceDisableRunAs{
    $stat = 'Fail'
    Write-Host "18.9.97.2.4 (L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    $reg_n = "DisableRunAs"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.98 Windows Remote Shell
function _18.9.98.1.WinRSAllowRemoteShellAccess{
    $stat = 'Fail'
    Write-Host "18.9.98.1 (L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS"
    $reg_n = "AllowRemoteShellAccess"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.99 Windows Security (formerly Windows Defender Security Center)
#18.9.99.1 Account protection
#18.9.99.2 App and browser protection
function _18.9.99.2.1.DisallowExploitProtectionOverride{
    $stat = 'Fail'
    Write-Host "18.9.99.2.1 (L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
    $reg_n = "DisallowExploitProtectionOverride"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#18.9.100 Windows SideShow
#18.9.101 Windows System Resource Manager
#18.9.102 Windows Update
#18.9.102.1 Windows Update for Business (formerly Defer Windows Updates)
function _18.9.102.1.1.Managepreviewbuilds{
    $stat = 'Fail'
    Write-Host "18.9.102.1.1 (L1) Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $reg_All = @('ManagePreviewBuilds','ManagePreviewBuildsPolicyValue')
    $done = 0
    foreach($reg_n in $reg_All){
        try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
        Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
        If($val -notlike ""){
            Write-Host "Command result: "$val; If($val -eq 1){$done += 1}}
        Else{
            Write-Host "Command result: Disabled or Not Configured"}
    }
    If($done -eq $reg_All.Length){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.102.1.2.WindowsUpdateFeature{
    $stat = 'Fail'
    Write-Host "18.9.102.1.2 (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $reg_All = @('DeferFeatureUpdates','DeferFeatureUpdatesPeriodInDays','BranchReadinessLevel')
    $done = 0
    foreach($reg_n in $reg_All){
        try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
        Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
        If($val -notlike "" -and $reg_n -like $reg_All[0]){
            Write-Host "Command result: "$val; If($val -eq 1){$done += 1}}
        ElseIf($val -notlike "" -and $reg_n -like $reg_All[1]){
            Write-Host "Command result: "$val; If($val -ge 180){$done += 1}}
        ElseIf($val -notlike "" -and $reg_n -like $reg_All[2]){
            Write-Host "Command result: "$val; If($val -eq 16){$done += 1}}
        Else{
            Write-Host "Command result: Disabled or Not Configured"}
    }
    If($done -eq $reg_All.Length){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.102.1.3.WindowsUpdateQuality{
    $stat = 'Fail'
    Write-Host "18.9.102.1.3 (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $reg_All = @('DeferQualityUpdates','DeferQualityUpdatesPeriodInDays')
    $done = 0
    foreach($reg_n in $reg_All){
        try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
        Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
        If($val -notlike "" -and $reg_n -like $reg_All[0]){
            Write-Host "Command result: "$val; If($val -eq 1){$done += 1}}
        ElseIf($val -notlike "" -and $reg_n -like $reg_All[1]){
            Write-Host "Command result: "$val; If($val -eq 0){$done += 1}}
        Else{
            Write-Host "Command result: Disabled or Not Configured"}
    }
    If($done -eq $reg_All.Length){$stat = "Pass"}
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.102.2.ConfigureAutomaticUpdates{
    $stat = 'Fail'
    Write-Host "18.9.102.2 (L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $reg_n = "NoAutoUpdate"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 4){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.102.3.Scheduledinstallday{
    $stat = 'Fail'
    Write-Host "18.9.102.3 (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $reg_n = "ScheduledInstallDay"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _18.9.102.4.NoAutoRebootWithLoggedOnUsers{
    $stat = 'Fail'
    Write-Host "18.9.102.4 (L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'"
    $reg_p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $reg_n = "NoAutoRebootWithLoggedOnUsers"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#19 Administrative Templates (User)
#19.1 Control Panel
#19.1.1 Add or Remove Programs
#19.1.2 Display
#19.1.3 Personalization (formerly Desktop Themes)
function _19.1.3.1.ScreenSaveActive{
    $stat = 'Fail'
    Write-Host "19.1.3.1 (L1) Ensure 'Enable screen saver' is set to 'Enabled'"
    $reg_p = "HKU:\${sid}\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
    $reg_n = "ScreenSaveActive"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _19.1.3.2.SCRNSAVE.EXE{
    $stat = 'Fail'
    Write-Host "19.1.3.2 (L1) Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr' "
    $reg_p = "HKU:\${sid}\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
    $reg_n = "SCRNSAVE.EXE"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _19.1.3.3.ScreenSaverIsSecure{
    $stat = 'Fail'
    Write-Host "19.1.3.3 (L1) Ensure 'Password protect the screen saver' is set to 'Enabled'"
    $reg_p = "HKU:\${sid}\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
    $reg_n = "ScreenSaverIsSecure"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _19.1.3.4.ScreenSaveTimeOut{
    $stat = 'Fail'
    Write-Host "19.1.3.4 (L1) Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0' "
    $reg_p = "HKU:\${sid}\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
    $reg_n = "ScreenSaveTimeOut"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -gt 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#19.2 Desktop
#19.3 Network
#19.4 Shared Folders
#19.5 Start Menu and Taskbar
#19.5.1 Notifications
function _19.5.1.1.NoToastApplicationNotificationOnLockScreen{
    $stat = 'Fail'
    Write-Host "19.5.1.1 (L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'"
    $reg_p = "HKU:\${sid}\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    $reg_n = "NoToastApplicationNotificationOnLockScreen"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#19.6 System
#19.6.1 Ctrl+Alt+Del Options
#19.6.2 Display
#19.6.3 Driver Installation
#19.6.4 Folder Redirection
#19.6.5 Group Policy
#19.6.6 Internet Communication Management
#19.6.6.1 Internet Communication settings
function _19.6.6.1.1.NoImplicitFeedback{
    $stat = 'Fail'
    Write-Host "19.6.6.1.1 (L2) Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'"
    $reg_p = "HKU:\${sid}\Software\Policies\Microsoft\Assistance\Client\1.0"
    $reg_n = "NoImplicitFeedback"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#19.7 Windows Components
#19.7.1 Add features to Windows 8 / 8.1 / 10 (formerly Windows Anytime Upgrade)
#19.7.2 App runtime
#19.7.3 Application Compatibility
#19.7.4 Attachment Manager
function _19.7.4.1.SaveZoneInformation{
    $stat = 'Fail'
    Write-Host "19.7.4.1 (L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'"
    $reg_p = "HKU:\${sid}\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
    $reg_n = "SaveZoneInformation"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 2){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _19.7.4.2.ScanWithAntiVirus{
    $stat = 'Fail'
    Write-Host "19.7.4.2 (L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'"
    $reg_p = "HKU:\${sid}\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
    $reg_n = "ScanWithAntiVirus"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 3){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#19.7.5 AutoPlay Policies
#19.7.6 Backup
#19.7.7 Cloud Content
function _19.7.7.1.ConfigureWindowsSpotlight{
    $stat = 'Fail'
    Write-Host "19.7.7.1 (L1) Ensure 'Configure Windows spotlight on lock screen' is set to Disabled'"
    $reg_p = "HKU:\${sid}\Software\Policies\Microsoft\Windows\CloudContent"
    $reg_n = "ConfigureWindowsSpotlight"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 2){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _19.7.7.2.DisableThirdPartySuggestions{
    $stat = 'Fail'
    Write-Host "19.7.7.2 (L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'"
    $reg_p = "HKU:\${sid}\Software\Policies\Microsoft\Windows\CloudContent"
    $reg_n = "DisableThirdPartySuggestions"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _19.7.7.3.DisableTailoredExperiencesWithDiagnosticData{
    $stat = 'Fail'
    Write-Host "19.7.7.3 (L2) Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'"
    $reg_p = "HKU:\${sid}\Software\Policies\Microsoft\Windows\CloudContent"
    $reg_n = "DisableTailoredExperiencesWithDiagnosticData"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
function _19.7.7.4.DisableWindowsSpotlightFeatures{
    $stat = 'Fail'
    Write-Host "19.7.7.4 (L2) Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'"
    $reg_p = "HKU:\${sid}\Software\Policies\Microsoft\Windows\CloudContent"
    $reg_n = "DisableWindowsSpotlightFeatures"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#19.7.8 Credential User Interface
#19.7.9 Data Collection and Preview Builds
#19.7.10 Desktop Gadgets
#19.7.11 Desktop Window Manager
#19.7.12 Digital Locker
#19.7.13 Edge UI
#19.7.14 File Explorer (formerly Windows Explorer)
#19.7.15 File Revocation
#19.7.16 IME
#19.7.17 Import Video
#19.7.18 Instant Search
#19.7.19 Internet Explorer
#19.7.20 Location and Sensors
#19.7.21 Microsoft Edge
#19.7.22 Microsoft Management Console
#19.7.23 Microsoft User Experience Virtualization
#19.7.24 NetMeeting
#19.7.25 Network Projector
#19.7.26 Network Sharing
function _19.7.26.1.NoInplaceSharing{
    $stat = 'Fail'
    Write-Host "19.7.26.1 (L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'"
    $reg_p = "HKU:\${sid}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $reg_n = "NoInplaceSharing"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#19.7.27 OOBE
#19.7.28 Presentation Settings
#19.7.29 Remote Desktop Services (formerly Terminal Services)
#19.7.30 RSS Feeds
#19.7.31 Search
#19.7.32 Sound Recorder
#19.7.33 Store
#19.7.34 Tablet PC
#19.7.35 Task Scheduler
#19.7.36 Windows Calendar
#19.7.37 Windows Color System
#19.7.38 Windows Defender SmartScreen
#19.7.39 Windows Error Reporting
#19.7.40 Windows Hello for Business (formerly Microsoft Passport for Work)
#19.7.41 Windows Installer
function _19.7.41.1.AlwaysInstallElevated{
    $stat = 'Fail'
    Write-Host "19.7.41.1 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
    $reg_p = "HKU:\${sid}\Software\Policies\Microsoft\Windows\Installer"
    $reg_n = "AlwaysInstallElevated"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 0){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}
#19.7.42 Windows Logon Options
#19.7.43 Windows Mail
#19.7.44 Windows Media Center
#19.7.45 Windows Media Player
#19.7.45.1 Networking
#19.7.45.2 Playback
function _19.7.45.2.1.PreventCodecDownload{
    $stat = 'Fail'
    Write-Host "19.7.45.2.1 (L2) Ensure 'Prevent Codec Download' is set to 'Enabled'"
    $reg_p = "HKU:\${sid}\Software\Policies\Microsoft\WindowsMediaPlayer"
    $reg_n = "PreventCodecDownload"
    try{ $val = Get-ItemPropertyValue $reg_p -Name $reg_n -ErrorAction SilentlyContinue}catch{$val = ""}
    Write-Host "Command:  Get-ItemPropertyValue $reg_p -Name $reg_n"
    
    If($val -notlike ""){Write-Host "Command result: "$val; If($val -eq 1){$stat = "Pass"}}
    Else{Write-Host "Command result: Disabled or Not Configured"}
    
    Write-Host "================================================="
    $stat
    Write-Host "================================================="
}

function universalcheck{
    Write-Host "*************************************************"
    Write-Host ">>>General INFO:"
    Write-Host "*************************************************"
    (Get-WmiObject Win32_OperatingSystem).name
	
	Write-Host "*************************************************"
    Write-Host ">>>Password policy:"
    Write-Host "*************************************************"
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
        $domanin = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object Domain
        Write-Host "This This computer is part of the domain: $domanin"
        $val = NET ACCOUNTS /DOMAIN
        foreach($param in $val)
        {
            Write-Host $param
        }
    } else {
        $val = NET ACCOUNTS
        foreach($param in $val)
        {
            Write-Host $param
        }
    }
	
    Write-Host "*************************************************"
    Write-Host ">>>Drive free space:"
    Write-Host "*************************************************"
    Get-PSDrive

    Write-Host "*************************************************"
    Write-Host ">>>Antivirus:"
    Write-Host "*************************************************"
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue

    Write-Host "*************************************************"
    Write-Host ">>>Antivirus STAT:"
    Write-Host "*************************************************"
    Get-MpComputerStatus

    Write-Host "*************************************************"
    Write-Host ">>>Updates:"
    Write-Host "*************************************************"
    (New-Object -com "Microsoft.Update.AutoUpdate"). Results | fl

    Write-Host "*************************************************"
    Write-Host ">>>Last Updates Installed:"
    Write-Host "*************************************************"
    gwmi win32_quickfixengineering |sort installedon -desc 

    Write-Host "*************************************************"
    Write-Host ">>>Local User:"
    Write-Host "*************************************************"
    Get-LocalUser
    Write-Host "*************************************************"
     $localGroup = Get-LocalGroup | Select Name
    foreach($group in $localGroup )
    {
        #Get-LocalGroupMember $group.Name
        Write-Host "User member for group:" $group.Name
        $user = Get-LocalGroupMember $group.Name | Select Name, PrincipalSource, ObjectClass
        $user
        
    }
    Write-Host "*************************************************"
    Write-Host ">>>List of instaled app:"
    Write-Host "*************************************************"
    Get-WmiObject -Class  Win32_product | Select Name, Version 

    Write-Host "*************************************************"
    Write-Host "***********************END***********************"
    Write-Host "*************************************************"
 }
#=======================================================================================
##                               FUNCTIONS END
#=======================================================================================
#Divizarea functiilor pe nivele
#Level 1
function Level_1_Domain_Controller{
    _2.2.2.AccessComputerFromNetworkDC	
    _2.2.5.AccessAddWorkstationsDC	
    _2.2.8.LogonThroughRemoteDesktopServicesDC	
    _2.2.17.CreateSymbolicLinksDC	
    _2.2.20.DenyNetworkAccessDC	
    _2.2.25.DenyRemoteDesktopServiceLogonDC	
    _2.2.27.AdminTrustedForDelegationDC	
    _2.2.31.ImpersonateClientAfterAuthenticationDC	
    _2.2.37.ManageAuditingAndSecurityDC	
    _2.2.47.NoOneSynchDirServDataDC	
    _2.3.5.1.AlowServOperToSchedTasksDisDC	
    _2.3.5.2.LDAPServSetToReqSignDC	
    _2.3.5.3.RefuseMachiAccPassChanTODisDC	
    _2.3.10.6.NullSessionPipesDC
	_17.1.2.AuditKerberosAuthServiceDC
	_17.1.3.AuditKerbServTicketOperDC	
    _17.2.2.AuditComputerAccountManagementDC	
    _17.2.3.AuditDistribGroupManagementDC	
    _17.2.4.AuditOtherAccountManagementEventsDC	
    _17.4.1.AuditDirectoryServiceAccessDC	
    _17.4.2.AuditDirectoryServiceChangesDC	
    _18.3.5.LdapEnforceChannelBindingDC	
    _18.8.5.6.LsaCfgFlagDC
}

function Level_1_Member_Server{
    _2.2.3.AccessComputerFromNetwork		 
    _2.2.9.LogonThroughRemoteDesktopServices		 
    _2.2.18.CreateSymbolicLinks		 
    _2.2.21.DenyNetworkAccess		 
    _2.2.26.DenyRemoteDesktopServiceLogon		 
    _2.2.28.NoOneTrustedForDelegation		 
    _2.2.32.ImpersonateClientAfterAuthentication		 
    _2.2.38.ManageAuditingAndSecurity		 
    _2.3.1.1.DisableAdministratorAccount		 
    _2.3.1.3.DisableGuestAccount		 
    _2.3.7.8.RequireDomainControllerAuth		 
    _2.3.9.5.LanManServerSmbServerNameHardeningLevel		 
    _2.3.10.2.RestrictAnonymousSAM		 
    _2.3.10.3.RestrictAnonymous		 
    _2.3.10.7.NullSessionPipes		 
    _2.3.10.11.RestrictRemoteSAM		 
    _18.2.1_18.2.6.LAPS		 	 
    _18.3.1.LocalAccountTokenFilterPolicy		 		 
    _18.8.5.5.LsaCfgFlags		 
    _18.8.28.4.EnumerateLocalUsers		 
    _18.8.37.1.EnableAuthEpResolution
}

function Level_1_Domain_Controller_Level_1_Member_Server{
    _1.1.1.EnforcePasswordHistory	
    _1.1.2.MaximumPasswordAge	
    _1.1.3.MinimumPasswordAge	
    _1.1.4.MinimumPasswordLength	
    _1.1.5.WindowsPasswordComplexityPolicyMustBeEnabled	
    _1.1.6.DisablePasswordReversibleEncryption	
    _1.2.1.AccountLockoutDuration	
    _1.2.2.AccountLockoutThreshold	
    _1.2.3.ResetAccountLockoutCounter	
    _2.2.1.NoOneTrustCallerACM	
    _2.2.4.NoOneActAsPartOfOperatingSystem	
    _2.2.6.AccessComputerFromNetwork	
    _2.2.7.AllowLogonLocallyToAdministrators	
    _2.2.10.BackupFilesAndDirectories	
    _2.2.11.ChangeSystemTime	
    _2.2.12.ChangeTimeZone	
    _2.2.13.CreatePagefile	
    _2.2.14.NoOneCreateTokenObject	
    _2.2.15.CreatePagefile	
    _2.2.16.NoOneCreateTokenObject	
    _2.2.19.DebugPrograms	
    _2.2.22.DenyGuestBatchLogon	
    _2.2.23.DenyGuestServiceLogon	
    _2.2.24.DenyGuestLocalLogon	
    _2.2.29.ForceShutdownFromRemoteSystem	
    _2.2.30.GenerateSecurityAudits	
    _2.2.33.IncreaseSchedulingPriority	
    _2.2.34.LoadUnloadDeviceDrivers	
    _2.2.35.NoOneLockPagesInMemory	
    _2.2.39.NoOneModifiesObjectLabel	
    _2.2.40.FirmwareEnvValues	
    _2.2.41.VolumeMaintenance	
    _2.2.42.ProfileSingleProcess	
    _2.2.43.ProfileSystemPerformance	
    _2.2.44.ReplaceProcessLevelToken	
    _2.2.45.RestoreFilesDirectories	
    _2.2.46.RestoreFilesDirectories	
    _2.2.48.TakeOwnershipFiles	
    _2.3.1.2.DisableMicrosoftAccounts	
    _2.3.1.4.LimitBlankPasswordConsole	
    _2.3.1.5.RenameAdministratorAccount	
    _2.3.1.6.RenameGuestAccount	
    _2.3.2.1.AuditForceSubCategoryPolicy	
    _2.3.2.2.AuditForceShutdown	
    _2.3.4.1.DevicesAdminAllowedFormatEject	
    _2.3.4.2.PreventPrinterInstallation	
    _2.3.6.1.SignEncryptAllChannelData	
    _2.3.6.2.SecureChannelWhenPossible	
    _2.3.6.3.DigitallySignChannelWhenPossible	
    _2.3.6.4.EnableAccountPasswordChanges	
    _2.3.6.5.MaximumAccountPasswordAge	
    _2.3.6.6.RequireStrongSessionKey	
    _2.3.7.1.RequireCtlAltDel	
    _2.3.7.2.DontDisplayLastSigned	
    _2.3.7.3.MachineInactivityLimit	
    _2.3.7.4.LogonLegalNotice	
    _2.3.7.5.LogonLegalNoticeTitle	
    _2.3.7.7.PromptUserPassExpiration	
    _2.3.7.9.SmartCardRemovalBehaviour	
    _2.3.8.1.NetworkClientSignCommunications	
    _2.3.8.2.EnableSecuritySignature	
    _2.3.8.3.DisableSmbUnencryptedPassword	
    _2.3.9.1.IdleTimeSuspendingSession	
    _2.3.9.2.NetworkServerAlwaysDigitallySign	
    _2.3.9.3.LanManSrvEnableSecuritySignature	
    _2.3.9.4.LanManServerEnableForcedLogOff	
    _2.3.10.1.LSAAnonymousNameDisabled	
    _2.3.10.5.EveryoneIncludesAnonymous	
    _2.3.10.8.AllowedExactPaths	
    _2.3.10.9.AllowedPaths	
    _2.3.10.10.RestrictNullSessAccess	
    _2.3.10.12.NullSessionShares	
    _2.3.10.13.LsaForceGuest	
    _2.3.11.1.LsaUseMachineId	
    _2.3.11.2.AllowNullSessionFallback	
    _2.3.11.3.AllowOnlineID	
    _2.3.11.4.SupportedEncryptionTypes	
    _2.3.11.5.NoLMHash	
    _2.3.11.6.ForceLogoff	
    _2.3.11.7.LmCompatibilityLevel	
    _2.3.11.8.LDAPClientIntegrity	
    _2.3.11.9.NTLMMinClientSec	
    _2.3.11.10.NTLMMinServerSec	
    _2.3.13.1.ShutdownWithoutLogon	
    _2.3.15.1.ObCaseInsensitive	
    _2.3.15.2.SessionManagerProtectionMode	
    _2.3.17.1.FilterAdministratorToken	
    _2.3.17.2.ConsentPromptBehaviorAdmin	
    _2.3.17.3.ConsentPromptBehaviorUser	
    _2.3.17.4.EnableInstallerDetection	
    _2.3.17.5.EnableSecureUIAPaths	
    _2.3.17.6.EnableLUA	
    _2.3.17.7.PromptOnSecureDesktop	
    _2.3.17.8.EnableVirtualization	
    _9.1.1.EnableVirtualization	
    _9.1.2.DomainDefaultInboundAction	
    _9.1.3.DomainDefaultOutboundAction	
    _9.1.4.DomainDisableNotifications	
    _9.1.5.DomainLogFilePath	
    _9.1.6.DomainLogFileSize	
    _9.1.7.DomainLogDroppedPackets	
    _9.1.8.DomainLogSuccessfulConnections	
    _9.2.1.PrivateEnableFirewall	
    _9.2.2.PrivateDefaultInboundAction	
    _9.2.3.PrivateDefaultOutboundAction	
    _9.2.4.PrivateDisableNotifications	
    _9.2.5.PrivateLogFilePath	
    _9.2.6.PrivateLogFileSize	
    _9.2.7.PrivateLogDroppedPackets	
    _9.2.8.PrivateLogSuccessfulConnections	
    _9.3.1.PublicEnableFirewall	
    _9.3.2.PublicDefaultInboundAction	
    _9.3.3.PublicDefaultOutboundAction	
    _9.3.4.PublicDisableNotifications	
    _9.3.5.PublicAllowLocalPolicyMerge	
    _9.3.6.PublicAllowLocalIPsecPolicyMerge	
    _9.3.7.PublicLogFilePath	
    _9.3.8.PublicLogFileSize	
    _9.3.9.PublicLogDroppedPackets	
    _9.3.10.PublicLogSuccessfulConnections	
    _17.1.1.AuditCredentialValidation	
    _17.2.1.AuditComputerAccountGroupManagement	
    _17.2.5.AuditSecurityGroupManagement	
    _17.2.6.AuditSecurityGroupManagement	
    _17.3.1.AuditPNPActivity	
    _17.3.2.AuditProcessCreation	
    _17.5.1.AuditAccountLockout	
    _17.5.2.AuditGroupMembership	
    _17.5.3.AuditLogoff	
    _17.5.4.AuditLogon	
    _17.5.5.AuditOtherLogonLogoffEvents	
    _17.5.6.AuditSpecialLogon	
    _17.6.1.AuditDetailedFileShare	
    _17.6.2.AuditFileShare	
    _17.6.3.AuditOtherObjectAccessEvents	
    _17.6.4.AuditRemovableStorage	
    _17.7.1.AuditPolicyChange	
    _17.7.2.AuditAuthenticationPolicyChange	
    _17.7.3.AuditAuthorizationPolicyChange	
    _17.7.4.AuditMPSSVCRuleLevelPolicyChange	
    _17.7.5.AuditOtherPolicyChangeEvents	
    _17.8.1.AuditSpecialLogon	
    _17.9.1.AuditIPsecDriver	
    _17.9.2.AuditOtherSystemEvents	
    _17.9.3.AuditSecurityStateChange	
    _17.9.4.AuditSecuritySystemExtension	
    _17.9.5.AuditSystemIntegrity	
    _18.1.1.1.PreventEnablingLockScreenCamera	
    _18.1.1.2.PreventEnablingLockScreenSlideShow	
    _18.1.2.2.PreventEnablingLockScreenSlideShow	
    _18.3.2.ConfigureSMBv1ClientDriver	
    _18.3.3.ConfigureSMBv1server	
    _18.3.4.DisableExceptionChainValidation	
    _18.3.6.NetBIOSNodeType
	_18.3.7.WDigestUseLogonCredential	
    _18.4.1.WinlogonAutoAdminLogon	
    _18.4.2.DisableIPv6SourceRouting	
    _18.4.3.DisableIPv4SourceRouting	
    _18.4.4.EnableICMPRedirect	
    _18.4.6.NoNameReleaseOnDemand	
    _18.4.8.SafeDllSearchMode	
    _18.4.9.ScreenSaverGracePeriod	
    _18.4.12.SecurityWarningLevel
	_18.5.4.1.EnableMulticast	
    _18.5.8.1.AllowInsecureGuestAuth	
    _18.5.11.2.PeernetDisabled	
    _18.5.11.3.ProhibitInternetConnectionSharing	
    _18.5.11.4.StdDomainUserSetLocation	
    _18.5.14.1.HardenedPaths	
    _18.5.21.1.fMinimizeConnections	
    _18.8.3.1.ProcessCreationIncludeCmdLine	
    _18.8.4.1.EncryptionOracleRemediation	
    _18.8.4.2.AllowProtectedCreds	
    _18.8.5.1.EnableVirtualizationBasedSecurity	
    _18.8.5.2.RequirePlatformSecurityFeatures	
    _18.8.5.3.HypervisorEnforcedCodeIntegrity	
    _18.8.5.4.HVCIMATRequired	
    _18.8.5.7.ConfigureSystemGuardLaunch	
    _18.8.14.1.DriverLoadPolicy	
    _18.8.21.2.NoBackgroundPolicy	
    _18.8.21.3.NoGPOListChanges	
    _18.8.21.4.EnableCdp	
    _18.8.21.5.DisableBkGndGroupPolicy	
    _18.8.22.1.1.DisableWebPnPDownload	
    _18.8.22.1.5.NoWebServices	
    _18.8.26.1.DeviceEnumerationPolicy	
    _18.8.28.1.BlockUserFromShowingAccountDetailsOnSignin	
    _18.8.28.2.DontDisplayNetworkSelectionUI	
    _18.8.28.3.DontEnumerateConnectedUsers	
    _18.8.28.5.DisableLockScreenAppNotifications	
    _18.8.28.6.BlockDomainPicturePassword	
    _18.8.28.7.AllowDomainPINLogon	
    _18.8.34.6.3.RequirePasswordWakes	
    _18.8.34.6.4.RequirePasswordWakesAC	
    _18.8.36.1.fAllowUnsolicited	
    _18.8.36.2.fAllowToGetHelp	
    _18.9.6.1.MSAOptional	
    _18.9.8.1.NoAutoplayfornonVolume	
    _18.9.8.2.NoAutorun	
    _18.9.8.3.NoDriveTypeAutoRun	
    _18.9.10.1.1.EnhancedAntiSpoofing	
    _18.9.13.1.DisableWindowsConsumerFeatures	
    _18.9.14.1.RequirePinForPairing	
    _18.9.15.1.DisablePasswordReveal	
    _18.9.15.2.DisableEnumerateAdministrators	
    _18.9.16.1.DisallowTelemetry	
    _18.9.16.3.DoNotShowFeedbackNotifications	
    _18.9.16.4.AllowBuildPreview	
    _18.9.26.1.1.EventLogRetention	
    _18.9.26.1.2.EventLogMaxSize	
    _18.9.26.2.1.EventLogSecurityRetention	
    _18.9.26.2.2.EventLogSecurityMaxSize	
    _18.9.26.3.1.EventLogSetupRetention	
    _18.9.26.3.2.EventLogSetupMaxSize	
    _18.9.26.4.1.EventLogSystemRetention	
    _18.9.26.4.2.EventLogSystemMaxSize	
    _18.9.30.2.NoDataExecutionPrevention	
    _18.9.30.3.NoHeapTerminationOnCorruption	
    _18.9.30.4.PreXPSP2ShellProtocolBehavior	
    _18.9.44.1.MicrosoftAccountDisableUserAuth	
    _18.9.52.1.OneDriveDisableFileSyncNGSC	
    _18.9.59.2.2.TerminalServicesDisablePasswordSaving	
    _18.9.59.3.3.2.TerminalServicesfDisableCdm	
    _18.9.59.3.9.1.TerminalServicesfPromptForPassword	
    _18.9.59.3.9.2.TerminalServicesfEncryptRPCTraffic	
    _18.9.59.3.9.3.TerminalServicesSecurityLayer	
    _18.9.59.3.9.4.TerminalServicesUserAuthentication	
    _18.9.59.3.9.5.TerminalServicesMinEncryptionLevel	
    _18.9.59.3.11.1.TerminalServicesDeleteTempDirsOnExit	
    _18.9.59.3.11.2.TerminalServicesPerSessionTempDir	
    _18.9.60.1.DisableEnclosureDownload	
    _18.9.61.3.AllowIndexingEncryptedStoresOrItems	
    _18.9.77.3.1.LocalSettingOverrideSpynetReporting	
    _18.9.77.7.1.DisableBehaviorMonitoring	
    _18.9.77.10.1.DisableRemovableDriveScanning	
    _18.9.77.10.2.DisableEmailScanning	
    _18.9.77.13.1.1.ExploitGuard_ASR_Rules	
    _18.9.77.13.1.2.ConfigureASRrules	
    _18.9.77.13.3.1.EnableNetworkProtection	
    _18.9.77.14.PUAProtection	
    _18.9.77.15.DisableAntiSpyware	
    _18.9.80.1.1.DefenderSmartScreen	
    _18.9.84.2.AllowWindowsInkWorkspace	
    _18.9.85.1.InstallerEnableUserControl	
    _18.9.85.2.InstallerAlwaysInstallElevated	
    _18.9.86.1.DisableAutomaticRestartSignOn	
    _18.9.95.1.EnableScriptBlockLogging	
    _18.9.95.2.EnableTranscripting	
    _18.9.97.1.1.WinRMClientAllowBasic	
    _18.9.97.1.2.WinRMClientAllowUnencryptedTraffic	
    _18.9.97.1.3.WinRMClientAllowDigest	
    _18.9.97.2.1.WinRMServiceAllowBasic	
    _18.9.97.2.3.WinRMServiceAllowUnencryptedTraffic	
    _18.9.97.2.4.WinRMServiceDisableRunAs	
    _18.9.99.2.1.DisallowExploitProtectionOverride	
    _18.9.102.1.1.Managepreviewbuilds	
    _18.9.102.1.2.WindowsUpdateFeature	
    _18.9.102.1.3.WindowsUpdateQuality	
    _18.9.102.2.ConfigureAutomaticUpdates	
    _18.9.102.3.Scheduledinstallday	
    _18.9.102.4.NoAutoRebootWithLoggedOnUsers	
    _19.1.3.1.ScreenSaveActive	
    _19.1.3.2.SCRNSAVE.EXE	
    _19.1.3.3.ScreenSaverIsSecure	
    _19.1.3.4.ScreenSaveTimeOut	
    _19.5.1.1.NoToastApplicationNotificationOnLockScreen	
    _19.7.4.1.SaveZoneInformation	
    _19.7.4.2.ScanWithAntiVirus	
    _19.7.7.1.ConfigureWindowsSpotlight	
    _19.7.7.2.DisableThirdPartySuggestions	
    _19.7.26.1.NoInplaceSharing	
    _19.7.41.1.AlwaysInstallElevated
}

#Level 2
function Level_2_Domain_Controller{
    _2.2.36.LogBatchJobToAdminDC
}

function Level_2_Member_Server{
    _2.3.7.6.PreviousLogonCache		 
    _18.5.21.2.fBlockNonDomain
    _18.8.37.2.RestrictRemoteClients
    _18.8.50.1.2.DisableWindowsNTPServer
}

function Level_2_Domain_Controller_Level_2_Member_Server{
    _2.3.10.4.DisableDomainCreds	
    _18.1.3.DisallowOnlineTips	
    _18.4.5.TcpIpKeepAliveTime	
    _18.4.7.PerformRouterDiscovery	
    _18.4.10.TcpMaxDataRetransmissionsV6	
    _18.4.11.TcpMaxDataRetransmissions	
    _18.5.5.1.EnableFontProviders	
    _18.5.9.1.LLTDIODisabled	
    _18.5.9.2.RSPNDRDisabled	
    _18.5.10.2.PeernetDisabled	
    _18.5.19.2.1.DisableIPv6DisabledComponents	
    _18.5.20.1.DisableConfigurationWirelessSettings	
    _18.5.20.2.ProhibitaccessWCNwizards	
    _18.7.1.1.NoCloudApplicationNotification	
    _18.8.22.1.2.PreventHandwritingDataSharing	
    _18.8.22.1.3.PreventHandwritingErrorReports	
    _18.8.22.1.4.ExitOnMSICW	
    _18.8.22.1.6.DisableHTTPPrinting	
    _18.8.22.1.7.NoRegistration	
    _18.8.22.1.8.DisableContentFileUpdates	
    _18.8.22.1.9.NoOnlinePrintsWizard	
    _18.8.22.1.10.NoPublishingWizard	
    _18.8.22.1.11.CEIP	
    _18.8.22.1.12.CEIPEnable	
    _18.8.22.1.13.TurnoffWindowsErrorReporting	
    _18.8.25.1.SupportDeviceAuthenticationUsingCertificate	
    _18.8.27.1.BlockUserInputMethodsForSignIn	
    _18.8.31.1.AllowCrossDeviceClipboard	
    _18.8.31.2.UploadUserActivities	
    _18.8.34.6.1.AllowNetworkBatteryStandby	
    _18.8.34.6.2.AllowNetworkACStandby	
    _18.8.45.5.1.DisableQueryRemoteServer	
    _18.8.45.11.1.ScenarioExecutionEnabled	
    _18.8.47.1.DisabledAdvertisingInfo	
    _18.8.50.1.1.NtpClientEnabled	
    _18.9.4.AllowSharedLocalAppData	
    _18.9.12.1.DisallowCamera	
    _18.9.16.2.DisableEnterpriseAuthProxy	
    _18.9.39.2.LocationAndSensorsDisableLocation	
    _18.9.43.1.MessagingAllowMessageSync	
    _18.9.59.3.2.1.fSingleSessionPerUser	
    _18.9.59.3.3.1.TerminalServicesfDisableCcm	
    _18.9.59.3.3.3.TerminalServicesfDisableLPT	
    _18.9.59.3.3.4.TerminalServicesfDisablePNPRedir	
    _18.9.59.3.10.1.TerminalServicesMaxIdleTime	
    _18.9.59.3.10.2.TerminalServicesMaxDisconnectionTime	
    _18.9.61.2.WindowsSearchAllowCloudSearch	
    _18.9.66.1.NoGenTicket	
    _18.9.77.3.2.SpynetReporting	
    _18.9.77.9.1.DisableGenericRePorts	
    _18.9.84.1.AllowSuggestedAppsInWindowsInkWorkspace	
    _18.9.85.3.InstallerSafeForScripting	
    _18.9.97.2.2.WinRMServiceAllowAutoConfig	
    _18.9.98.1.WinRSAllowRemoteShellAccess	
    _19.6.6.1.1.NoImplicitFeedback	
    _19.7.7.3.DisableTailoredExperiencesWithDiagnosticData	
    _19.7.7.4.DisableWindowsSpotlightFeatures	
    _19.7.45.2.1.PreventCodecDownload
}
#=======================================================================================
##                               FUNCTIONS LEVEL END
#=======================================================================================

#Verificam daca consola este pornita cu drepturi de admin
Write-Host "Se verifică dacă există permisiuni de executie..."
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole] "Administrator")) {
Write-Warning "Permisiuni insuficiente pentru a rula acest script. Deschideți consola PowerShell ca administrator și rulați din nou acest script."
Break
}
else { Write-Host "Codul rulează ca administrator..." -ForegroundColor Green }

#Start MAIN

If($args.count -eq 4 -and $args[0] -like "-L" -and $args[2] -like "-R")
{
    #Run write Transcript
    $machine = hostname
    $data = Get-Date -Format "_MM_dd_yyyy"
    $trfilename = "Audit_Evidence_WinSer_" + $machine + $data
    
    If(Test-Path -Path .\$trfilename -PathType Leaf){Remove-Item .\$trfilename}
    Start-Transcript -Path ".\$trfilename" -NoClobber
    
    #Pentru a extrage configuratiile la nivel de user
    $User = New-Object System.Security.Principal.NTAccount($env:UserName)
    $sid = $User.Translate([System.Security.Principal.SecurityIdentifier]).value
    
    #Exportam configuratiile pentru politica de securitate locala
    secedit /export /cfg ${env:appdata}\secpol.cfg | out-null
    
    ##Pentru a se testa  nivele 1
    If($args[1] -like "1"){
       If($args[3] -like "DC"){
            Write-Host "Level 1: Domain Controller"
            Write-Host "*************************************************"
            Level_1_Domain_Controller
       }
       ElseIf($args[3] -like "MS"){
       Write-Host "Level 1: Member Server"
       Write-Host "*************************************************"
            Level_1_Member_Server
       }
       Level_1_Domain_Controller_Level_1_Member_Server
    }
    ##Pentru a se testa  nivele 2
    ElseIf($args[1] -like "2"){
       If($args[3] -like "DC"){
            Write-Host "Level 2: Domain Controller"
            Write-Host "*************************************************"
            Level_2_Domain_Controller     
       }
       If($args[3] -like "MS"){
            Write-Host "Level 2: Member Server"
            Write-Host "*************************************************"
            Level_2_Member_Server
       }
       Level_2_Domain_Controller_Level_2_Member_Server
    }
    ##Pentru a se testa ambele nivele 1 si 2
    ElseIf($args[1] -like "1,2"){
       If($args[3] -like "DC"){
            Write-Host "Level 1,2: Domain Controller"
            Write-Host "*************************************************"
            Level_1_Domain_Controller
            Level_2_Domain_Controller
       }
       If($args[3] -like "MS"){
            Write-Host "Level 1,2: Member Server"
            Write-Host "*************************************************"
            Level_1_Member_Server 
            Level_2_Member_Server
       }
       Level_1_Domain_Controller_Level_1_Member_Server
       Level_2_Domain_Controller_Level_2_Member_Server
    }
}
Else{
    Write-Warning "Comanda introdusa nu poate fi prelucrata!!!"
    Write-Host "`

> Pentru a executa scriptul și obține probele este necesar să se urmeze următoarele etape:

	1. Se rulează consola "'PowerShell'" cu drepturi de administrator.
		- Apăsați tasta Win + R. O fereastră mică va apărea.
		- Tastați powershell și apăsați Ctrl + Shift + Enter.
		- Alte metode: https://adamtheautomator.com/powershell-run-as-administrator/
		
	2. În fereastra PowerShell deschisă, schimbăm path-ul către folderul în care este copiat scriptul, exemplu:
		- Set-Location C:\Users\username\Downloads
			or
		- cd C:\Users\username\Downloads
				
	3. Executam scriptul conform nivelului necesar și rolul serverului ce urmează a fi verificat (vezi mai jos Exemple de utilizare):
		.\scriptname.ps1 -L "'"1,2"'" -R DC
		
	4. Asteptam finisarea execuției pină se va afișa mesajul "'DONE!'".
	
	5. După finisarea execuției, în folderul părinte al scriptului va fi creată automat un fișier cu denumirea "'Audit_Evidence_WinSer.*'", necesară de copiat și de expediat către BSD. 
	

> Semnificația argumentelor:

	-L (Level) - argument utilizat pentru a se indica nivelul, contoalelor, dorit pentru verificare. 
		Obțiuni posibele:
			- 1 - testarea controalelor CIS de nivelul 1;
			- 2 - testarea controalelor CIS de nivelul 2;
			- "'"1,2"'" - testarea controalelor CIS de nivelul 1 și 2;
	-R (Role) - argument utilizat pentru a se indica rolul dserverului ce urmează a fi testat.
		Obțiuni posibile:
			- DC - Serverul ce urmează a fi testat deține rolul de Domen Controler
			- MS - Serverul ce urmează a fi testat deține rolul de Server Membru.
		
> Exemple de utilizare:
	- Pentru verificarea cofigurațiilor de "'Nivelul 1'", a unui server cu rolul de "'Domen Controler'", se utilizează comanda:
	.\scriptname.ps1 -L 1 -R DC 
	
	- Pentru verificarea cofigurațiilor de "'Nivelul 1'", a unui server cu rolul de "'Server Membru'", se utilizează comanda:
	.\scriptname.ps1 -L 1 -R MS
	
	- Pentru verificarea cofigurațiilor de "'Nivelul 2'", a unui server cu rolul de "'Domen Controler'", se utilizează comanda:
	.\scriptname.ps1 -L 2 -R DC
	
	- Pentru verificarea cofigurațiilor de "'Nivelul 1'", a unui server cu rolul de "'Server Membru'", se utilizează comanda:
	.\scriptname.ps1 -L 2 -R MS
	
	- Pentru verificarea cofigurațiilor de "'Nivelul 1 și 2'", a unui server cu rolul de "'Domen Controler'", se utilizează comanda:
	.\scriptname.ps1 -L "'"1,2"'" -R DC
	
	- Pentru verificarea cofigurațiilor de "'Nivelul 1 și 2'", a unui server cu rolul de "'Server Membru'", se utilizează comanda:
	.\scriptname.ps1 -L "'"1,2"'" -R MS
    
    "
    break
}

universalcheck # Functia care testea unele controale generale
#End MAIN

#STOP write Transcript
Stop-Transcript

#Stergem fisierul in care am exportat configuratiile pentru politica de securitate locala.
Remove-Item -force ${env:appdata}\secpol.cfg -confirm:$false

#Remove-Variable * -ErrorAction SilentlyContinue; Remove-Module *; $error.Clear();
Clear-Host

Write-Host "DONE!

în folderul părinte al scriptului a fost creat automat fișierul: " $trfilename ", necesar de copiat și de expediat către BSD!
"
Remove-Variable * -ErrorAction SilentlyContinue; Remove-Module *; $error.Clear();