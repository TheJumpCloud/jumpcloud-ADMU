$ADMUKEY = "HKCU:\SOFTWARE\JCADMU"
if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {

   $appxmanifest = ($HOME + '\AppData\Local\JumpCloudADMU\appx_manifest.csv')
   $newList = Import-CSV $appxmanifest
   $output = @()
   foreach ($item in $newlist) {
      $output += Add-AppxPackage -DisableDevelopmentMode -Register "$($item.InstallLocation)\AppxManifest.xml" -Verbose *>&1
   }
   $output | Out-File "$HOME\AppData\Local\JumpCloudADMU\appx_manifestLog.txt"
}
else{
     exit
}

#TODO add UWP powershell fullscreen form