$SerialNumber = Get-WmiObject win32_bios
$Computername = 'Lenovo' + $SerialNumber.Serialnumber
Rename-Computer -NewName $Computername
#Restart-Computer