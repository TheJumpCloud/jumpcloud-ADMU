# Variables for testing:
$testUserPassword = '$T#st1234'
# Region for test user generation
$userTestingHash = @{
    testCase1 = @{
        Description = 'Test that user can be converted with different name'
        Username    = 'user.name';
        UserSID     = '';
        Password    = $testUserPassword;
        JCUsername  = 'Username.username';
        JCUserSID   = '';
    }
    testCase2 = @{
        Description = 'Test that user can be converted twthedifrerentomaer x2s'
        Username    = 'username';
        UserSID     = '';
        Password    = $testUserPassword;
        JCUsername  = 'newUsername';
        JCUserSID   = '';
    }
    #estCase3 = @{
    #   Description = 'Test that user can be converted with same name'
    #   Username    = 'sameUsername';
    #   UserSID     = '';
    #   Password    = $testUserPassword;
    #   JCUsername  = 'sameUsername';
    #   JCUserSID   = '';
    #
}

$JCCommandTestingHash = @{
    testCase1 = @{
        Description = 'Test that user can be converted with different name'
        Username    = 'ADMU_tester';
        UserSID     = '';
        Password    = $testUserPassword;
        JCUsername  = 'ADMU_migrated';
        JCUserSID   = '';
    }
    # testCase2 = @{
    #     Description = 'Test that user can be converted with different name x2'
    #     Username    = 'ADMU_tester_two';
    #     UserSID     = '';
    #     Password    = $testUserPassword;
    #     JCUsername  = 'ADMU_migrated_two';
    #     JCUserSID   = '';
    # }
}