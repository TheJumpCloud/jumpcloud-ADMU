Describe "BlockAccountLogin early-exit cleanup semantics" -Tag "Acceptance" {
    # Documents the PowerShell advanced-function behavior that caused CUT-5227:
    # a bare `break` outside a loop aborts the entire script and skips end{}, while
    # `return` from process{} still runs end{} (where Start-Migration restores the
    # BlockAccountLogin deny-logon policy).

    It "end{} runs when process{} exits with return (required for BlockAccountLogin restore)" {
        $script:endRan = $false
        $script:accountLoginBlocked = $false

        function Test-EarlyExitWithReturn {
            begin {
                $script:accountLoginBlocked = $true
            }
            process {
                # Mimic Confirm-API / install failed-gate paths in Start-Migration
                return
            }
            end {
                $script:endRan = $true
                if ($script:accountLoginBlocked) {
                    $script:accountLoginBlocked = $false
                }
            }
        }

        Test-EarlyExitWithReturn

        $script:endRan | Should -BeTrue
        $script:accountLoginBlocked | Should -BeFalse
    }

    It "end{} does not run when process{} uses break outside a loop (the pre-fix failure mode)" {
        # Run in a child process: bare break outside a loop aborts the entire script,
        # including any enclosing scriptblock in the same process.
        $childScript = @'
$script:endRan = $false
$script:accountLoginBlocked = $false
function Test-EarlyExitWithBreak {
    begin { $script:accountLoginBlocked = $true }
    process { break }
    end {
        $script:endRan = $true
        if ($script:accountLoginBlocked) { $script:accountLoginBlocked = $false }
    }
}
Test-EarlyExitWithBreak
# If break skipped end{}, this marker is never written:
Write-Output "END_RAN=$($script:endRan);BLOCKED=$($script:accountLoginBlocked);MARKER=reached"
'@

        $shell = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
        $output = & $shell -NoProfile -Command $childScript 2>&1 | Out-String

        # Child exits before writing MARKER because break aborts the script without end{}
        $output | Should -Not -Match 'MARKER=reached'
        $output | Should -Not -Match 'END_RAN=True'
    }
}
