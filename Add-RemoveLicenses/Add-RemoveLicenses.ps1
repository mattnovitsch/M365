<#
#Install Modeule for service
install-module MSOnline

#Connect to M365 services
Connect-MsolService

#>

#Find your current Account License SKUs
Get-MsolAccountSku 

#Assign location to each user.
Get-MsolUser -All | where {$_.UsageLocation -eq $null} | Set-MsolUser -UsageLocation US

#Get the users that have the current license you need to swap out.
$Users = Get-MsolUser -all | Where {$_.Licenses.AccountSkuId -contains "mattazurelabs:Flow_Free"} | Select UserPrincipalName

Foreach ($User in $Users)
{
    write-host "Adding mattazurelabs:WIN_DEF_ATP License to uesr:" $User.UserPrincipalName
    Set-MsolUserLicense -UserPrincipalName $User.UserPrincipalName -AddLicenses "mattazurelabs:ATA"
    write-host "Removing mattazurelabs:WIN_DEF_ATP License from uesr:" $User.UserPrincipalName
    Set-MsolUserLicense -UserPrincipalName $User.UserPrincipalName -RemoveLicenses "mattazurelabs:Flow_Free"
} 
 
