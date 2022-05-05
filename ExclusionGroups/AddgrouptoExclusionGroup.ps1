#Connect-AzureAD

#Exclude Group in Intune
$Group1 = Get-AzureADGroup -SearchString ExclusionGroup | Select objectid

#Group to be added to Exclude Group
$Group2 = Get-AzureADGroup -SearchString FinanceDevices | Select objectid

#Get current month
$Month = Get-Date -Format "MM"

If ($Month = 4)
{
    #Adds group2 to group1 so it is excluded
    Add-AzureADGroupMember -ObjectId $Group1 -RefObjectId $Group2
}

If($Month = 5)
{
    #Removes group2 from group1 so it is no longer excluded
    Remove-AzureADGroupMember -ObjectId $Group1 -MemberId $Group2
}