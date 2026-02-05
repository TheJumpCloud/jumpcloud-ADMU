function Write-ToLog {
   [CmdletBinding()]
   param
   (
      [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateNotNullOrEmpty()][Alias("LogContent")][string]$Message,
      [Parameter(Mandatory = $false)][Alias('LogPath')][string]$Path = "$(Get-WindowsDrive)\Windows\Temp\jcAdmu.log",
      [Parameter(Mandatory = $false)][ValidateSet("Error", "Warning", "Info", "Verbose")][string]$Level = "Info",
      [Parameter(Mandatory = $false)][string]$Step,
      [Parameter(Mandatory = $false)][switch]$MigrationStep
   )
   begin {
      $VerbosePreference = 'Continue'
   }
   process {
      if (!(Test-Path $Path)) {
         Write-Verbose "Creating $Path."
         New-Item $Path -Force -ItemType File | Out-Null
      }
      $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
      $levelText = $Level.ToUpper()
      $stepText = if ($Step) { "[$Step]" } else { "" }

      # Handle MigrationStep formatting
      if ($MigrationStep) {
         $totalWidth = 52
         $messageText = $Message
         $availableWidth = $totalWidth - $messageText.Length - 2  # -2 for spaces around message
         $paddingEach = [math]::Floor($availableWidth / 2)
         $paddingLeft = "=" * $paddingEach
         $paddingRight = "=" * ($availableWidth - $paddingEach)
         $formattedMessage = "$paddingLeft $messageText $paddingRight"
         # remove stepText if empty
         if ([string]::IsNullOrEmpty($stepText)) {
            $logMessage = "[$timestamp] [$levelText] $formattedMessage"
         } else {
            $logMessage = "[$timestamp] [$levelText] $stepText $formattedMessage"
         }
      } else {
         # remove stepText if empty
         if ([string]::IsNullOrEmpty($stepText)) {
            $logMessage = "[$timestamp] [$levelText] $Message"
         } else {
            $logMessage = "[$timestamp] [$levelText] $stepText $Message"
         }
      }

      # Write to appropriate pipeline and optionally to console
      switch ($Level) {
         'Error' { Write-Error $logMessage; if ($Script:AdminDebug) { Write-Host $logMessage } }
         'Warning' { Write-Warning $logMessage; if ($Script:AdminDebug) { Write-Host $logMessage } }
         'Info' { if ($Script:AdminDebug) { Write-Host $logMessage } }
         'Verbose' { Write-Verbose $logMessage; if ($Script:AdminDebug) { Write-Host $logMessage } }
      }

      if ($Script:ProgressBar) {
         # add a new line to each of the log messages in the UI log stream
         Update-LogTextBlock -LogText "$logMessage`r`n" -ProgressBar $Script:ProgressBar
      }
      Add-Content -Value $logMessage -Path $Path -Encoding utf8
   }
   end {}
}