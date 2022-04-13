#Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
#Import-Module -Name ActiveDirectory
$ADComputerinfo = get-adcomputer -identity $env:COMPUTERNAME -Properties *
$ComputerINT = $ADComputerinfo.ObjectCategory.IndexOf(",")
$ADComputerinfo.ObjectCategory.substring(3, $ComputerINT-3)

If(($ADComputerinfo.ObjectCategory.substring(3, $ComputerINT-3)) -eq "Computer" )
{
    $Computername = 'DC01' + $SerialNumber.Serialnumber
    $Computername
    #Rename-Computer -NewName $Computername
} 
