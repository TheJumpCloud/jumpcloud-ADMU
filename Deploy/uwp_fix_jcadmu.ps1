$ADMUKEY = "HKCU:\SOFTWARE\JCADMU"
if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {

$appxmanifest = ($HOME + '\AppData\Local\JumpCloudADMU\appx_manifest.csv')
$newList = Import-CSV $appxmanifest
foreach ($item in $newlist){
   Add-AppxPackage -DisableDevelopmentMode -Register "$($item.InstallLocation)\AppxManifest.xml"
}
}
else{
     exit
}