#Define variables for the path, key, and value
$registryPath = "HKCU:\Software\Microsoft\Office\16.0\Outlook\Options\Spelling"
$Name = "check"
$value = "1"

#check the path and key to see if its enabled or not.
#0 = disabled
#1 = enabled
If((Get-ItemProperty -Path HKCU:\Software\Microsoft\Office\16.0\Outlook\Options\Spelling\).check -eq 0)
{
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}