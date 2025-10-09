#Logging function
<#
  .Synopsis
     Write-ToLog writes a message to a specified log file with the current time stamp.
  .DESCRIPTION
     The Write-ToLog function is designed to add logging capability to other scripts.
     In addition to writing output and/or verbose you can write to a log file for
     later debugging.
  .NOTES
     Created by: Jason Wasser @wasserja
     Modified: 11/24/2015 09:30:19 AM
  .PARAMETER Message
     Message is the content that you wish to add to the log file.
  .PARAMETER Path
     The path to the log file to which you would like to write. By default the function will
     create the path and file if it does not exist.
  .PARAMETER Level
     Specify the criticality of the log information being written to the log (i.e. Error, Warning, Informational)
  .EXAMPLE
     Write-ToLog -Message 'Log message'
     Writes the message to c:\Logs\PowerShellLog.log.
  .EXAMPLE
     Write-ToLog -Message 'Restarting Server.' -Path c:\Logs\Scriptoutput.log
     Writes the content to the specified log file and creates the path and file specified.
  .EXAMPLE
     Write-ToLog -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error
     Writes the message to the specified log file as an error message, and writes the message to the error pipeline.
  .LINK
     https://gallery.technet.microsoft.com/scriptcenter/Write-ToLog-PowerShell-999c32d0
  #>
# Set a global parameter for debug logging

Function Write-ToLog {
   [CmdletBinding()]
   Param
   (
      [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateNotNullOrEmpty()][Alias("LogContent")][string]$Message,
      [Parameter(Mandatory = $false)][Alias('LogPath')][string]$Path = "$(Get-WindowsDrive)\Windows\Temp\jcAdmu.log",
      [Parameter(Mandatory = $false)][ValidateSet("Error", "Warning", "Info", "Verbose")][string]$Level = "Info",
      [Parameter(Mandatory = $false)][string]$Step
   )
   Begin {
      $VerbosePreference = 'Continue'
   }
   Process {
      if (!(Test-Path $Path)) {
         Write-Verbose "Creating $Path."
         New-Item $Path -Force -ItemType File | Out-Null
      }
      $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
      $levelText = $Level.ToUpper()
      $stepText = if ($Step) { "[$Step]" } else { "" }
      $logMessage = "[$timestamp] [$levelText] $stepText $Message"

      # Write to appropriate pipeline and optionally to console
      switch ($Level) {
         'Error' { Write-Error $logMessage; if ($Script:AdminDebug) { Write-Host $logMessage } }
         'Warn' { Write-Warning $logMessage; if ($Script:AdminDebug) { Write-Host $logMessage } }
         'Info' { if ($Script:AdminDebug) { Write-Host $logMessage } }
         'Verbose' { Write-Verbose $logMessage; if ($Script:AdminDebug) { Write-Host $logMessage } }
      }

      if ($Script:ProgressBar) {
         # add a new line to each of the log messages in the UI log stream
         Update-LogTextBlock -LogText "$logMessage`r`n" -ProgressBar $Script:ProgressBar
      }
      Add-Content -Value $logMessage -Path $Path -Encoding utf8
   }
   End {}
}