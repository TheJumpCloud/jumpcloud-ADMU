# Variables for testing:
$testUserPassword = '$T#st1234'
# Region for test user generation
$userTestingHash = @{
    testCase1 = @{
        Description = 'Test that user can be converted'
        Username    = 'user.name';
        UserSID     = '';
        Password    = $testUserPassword;
        JCUsername  = 'User.Name';
        JCUserSID   = '';
    }
    testCase2 = @{
        Description = 'Test that user can be converted twice for random errors'
        Username    = 'username';
        UserSID     = '';
        Password    = $testUserPassword;
        JCUsername  = 'newUsername';
        JCUserSID   = '';
    }
    testCase2 = @{
        Description = 'Test that user can be converted with same name'
        Username    = 'sameUsername';
        UserSID     = '';
        Password    = $testUserPassword;
        JCUsername  = 'sameUsername';
        JCUserSID   = '';
    }
}