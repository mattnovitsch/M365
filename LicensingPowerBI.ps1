#required module
If (Get-Module -ListAvailable -Name AzureAD)
{
     Write-Host "Module exists"
}
Else
{
Install-Module -Name AzureAD
}
If (Get-Module -ListAvailable -Name MSOnline)
{
     Write-Host "Module exists"
}
Else
{
    Install-Module -Name MSOnline
}

#Connections
If (Get-MsolDomain -ErrorAction SilentlyContinue)
{
    Write-Host "Still connected"
}
Else
{
    Connect-MsolService
}

If (Get-AzureADTenantDetail)
{
    Write-Host "Still connected"
}
Else
{
    Connect-AzureAD
}


$RetrieveDate = Get-Date 
$ADUsers = Get-AzureADUser -All $true | Select-Object ObjectId, ObjectType, CompanyName, Department, DisplayName, JobTitle, Mail, Mobile, `
            SipProxyAddress, TelephoneNumber, UserPrincipalName, UserType, @{Name="Date Retrieved";Expression={$RetrieveDate}}

$OrgO365Licenses = Get-AzureADSubscribedSku | Select-Object SkuID, SkuPartNumber,CapabilityStatus, ConsumedUnits -ExpandProperty PrepaidUnits | `
    Select-Object SkuID,SkuPartNumber,CapabilityStatus,ConsumedUnits,Enabled,Suspended,Warning, @{Name="Retrieve Date";Expression={$RetrieveDate}} 
     
$UserLicenseDetail = ForEach ($ADUser in $ADUsers)
    {
        $UserObjectID = $ADUser.ObjectId
        $UPN = $ADUser.UserPrincipalName
        $UserName = $ADUser.DisplayName
        $UserDept = $ADUser.Department
        Get-AzureADUserLicenseDetail -ObjectId $UserObjectID -ErrorAction SilentlyContinue | `
        Select-Object ObjectID, @{Name="User Name";Expression={$UserName}},@{Name="UserPrincipalName";Expression={$UPN}}, `
        @{Name="Department";Expression={$UserDept}},@{Name="Retrieve Date";Expression={$RetrieveDate}} -ExpandProperty ServicePlans
    }

$ProUsers = $UserLicenseDetail
$ProUsers | Select-Object -Property "User Name", UserPrincipalName, Department, Appliesto, ProvisioningStatus, ServicePlanName | export-csv -Path .\Data.csv -NoTypeInformation