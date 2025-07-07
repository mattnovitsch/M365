Unregister-ScheduledTask -TaskName "NetworkProtection" -Confirm:$false
Unregister-ScheduledTask -TaskName "DownloadEICARFile" -Confirm:$false
Unregister-ScheduledTask -TaskName "DownloadPUAFile" -Confirm:$false
Unregister-ScheduledTask -TaskName "ORADAD" -Confirm:$false
Unregister-ScheduledTask -TaskName "Recon" -Confirm:$false
Unregister-ScheduledTask -TaskName "RemotePowerShell" -Confirm:$false
Unregister-ScheduledTask -TaskName "RemoveDefender" -Confirm:$false
Unregister-ScheduledTask -TaskName "SuspiciousPowershell" -Confirm:$false