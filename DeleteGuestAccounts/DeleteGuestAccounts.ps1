Connect-MsolService
$Results = @();
$Users = Get-Content C:\HWID\Remove_guest.csv

$licensedUsers = Get-MsolUser -all | Where-Object { $_.UserType -eq "Guest" } | Select  UserPrincipalName,@{Name="AlternateEmailAddresses";Expression={$_.AlternateEmailAddresses}}
$licensedUsers | ForEach-Object {
$AlternateEmailAddresses = $_.AlternateEmailAddresses
$UPN = $_.UserPrincipalName
    If ($Users -eq "$AlternateEmailAddresses")
    {
        $Results += $UPN
        #Remove-MsolUser -UserPrincipalName $UPN -force
    }
}
$Results
