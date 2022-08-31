# Get info about the the Git Commit
# $CIRCLE_SHA1 = "6c6cb9745a807b6e40801f9a4179fb46923a8e88"
$CIRCLE_SHA1 = "2793e1e0c3cb80cef82565a3b80bdaf6f42a6aae"
$gitCommit = git show $CIRCLE_SHA1

$mergeRegex = [regex]"Merge pull request"
$commitMatch = Select-String -inputObject $gitCommit -Pattern $mergeRegex

if ($commitMatch){
    Write-Host $commitMatch.Matches.Value
}