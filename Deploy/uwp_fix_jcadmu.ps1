$ADMUKEY = "HKCU:\SOFTWARE\JCADMU"
if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {

   $appxmanifest = ($HOME + '\AppData\Local\JumpCloudADMU\appx_manifest.csv')
   $newList = Import-CSV $appxmanifest
   $output = foreach ($item in $newlist) {
      Add-AppxPackage -DisableDevelopmentMode -Register "$($item.InstallLocation)\AppxManifest.xml"
   }
   $output | Out-File "$HOME + '\AppData\Local\JumpCloudADMU\appx_manifestLog.txt"
}
else{
     exit
}