#Open in the background
$openAsHidden=$true

#Open after login
$openAtLogin=$true

#Keep running in background when we 'close' teams
$runningOnClose=$true

$jsonFile = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft', 'Teams', 'desktop-config.json')
      
if (Test-Path -Path $jsonFile) {   
    
    #Get Teams Configuration
    $jsonContent =Get-Content -Path $jsonFile -Raw
   
    #Convert file content from JSON format to PowerShell object
    $jsonObject = ConvertFrom-Json -InputObject $jsonContent
   
    #Update Object settings
        
        if ([bool]($jsonObject.appPreferenceSettings -match "OpenAsHidden")) {
            $jsonObject.appPreferenceSettings.OpenAsHidden=$openAsHidden
        } else {
            $jsonObject.appPreferenceSettings | Add-Member -Name OpenAsHidden -Value $openAsHidden -MemberType NoteProperty
        }
    
        if ([bool]($jsonObject.appPreferenceSettings -match "OpenAtLogin")) {
            $jsonObject.appPreferenceSettings.OpenAtLogin=$openAtLogin
        } else {
            $jsonObject.appPreferenceSettings | Add-Member -Name OpenAtLogin -Value $openAtLogin -MemberType NoteProperty
        }
                
        if ([bool]($jsonObject.appPreferenceSettings -match "RunningOnClose")) {
            $jsonObject.appPreferenceSettings.RunningOnClose=$runningOnClose
        } else {
            $jsonObject.appPreferenceSettings | Add-Member -Name RunningOnClose -Value $runningOnClose -MemberType NoteProperty
        }
           
        #Terminate Teams if it is running
        $teamsProcess = Get-Process Teams -ErrorAction SilentlyContinue
	    If ($teamsProcess) {

			    #Close Teams Window
  			    $teamsProcess.CloseMainWindow() | Out-Null
			    Sleep 5
		
           	    #Close Teams 
			    Stop-Process -Name "Teams" -Force -ErrorAction SilentlyContinue

	    }

        #Update configuration
        $jsonObject | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonFile -Force
         
        #Define Teams Update.exe paths      
        $userTeams = [System.IO.Path]::Combine("$env:LOCALAPPDATA", "Microsoft", "Teams", "current", "Teams.exe")
        $machineTeamsX86 = [System.IO.Path]::Combine("$env:PROGRAMFILES (X86)", "Microsoft", "Teams", "current", "Teams.exe")
        $machineTeamsX64 = [System.IO.Path]::Combine("$env:PROGRAMFILES", "Microsoft", "Teams", "current", "Teams.exe")
        
        #Define arguments
        $args = @("-process-start-args","""--system-initiated""")

        #Launch Teams
        if (Test-Path -Path $userTeams) {
            Start-Process -FilePath $userTeams -ArgumentList $args
        } elseif (Test-Path -Path $machineTeamsX86) {
            Start-Process -FilePath $machineTeamsX86 -ArgumentList $args
        } elseif (Test-Path -Path $machineTeamsX64) {
            Start-Process -FilePath $machineTeamsX64 -ArgumentList $args
        }

    }

#https://www.alkanesolutions.co.uk/2021/01/16/launch-microsoft-teams-minimised-in-the-system-tray/