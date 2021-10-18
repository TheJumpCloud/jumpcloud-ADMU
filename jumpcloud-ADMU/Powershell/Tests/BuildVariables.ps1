# Variables for testing:
$testUserPassword = '$T#st1234'
# Region for test user generation
$userTestingHash = @{
    testCase1 = @{
        Description     = 'Test that user can be converted with different name'
        Username        = 'test_case_1';
        UserSID         = '';
        Password        = $testUserPassword;
        JCUsername      = 'test_case_1_migrated';
        JCUserSID       = '';
        UpdateHomePath  = $false
    }
    testCase2 = @{
        Description     = 'Test that user can be converted with different name x2s'
        Username        = 'test_case_2';
        UserSID         = '';
        Password        = $testUserPassword;
        JCUsername      = 'test_case_2_migrated';
        JCUserSID       = '';
        UpdateHomePath  = $true
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
        Description    = 'Test that user can be converted with different name'
        Username       = 'ADMU_tester';
        UserSID        = '';
        Password       = $testUserPassword;
        JCUsername     = 'ADMU_migrated';
        JCUserSID      = '';
        UpdateHomePath = $false
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
$JCFunctionalHash = @{
    testCase1 = @{
        Description    = 'Test that user is jumpcloud bound to system after migration'
        Username       = 'ADMU_bind';
        UserSID        = '';
        Password       = $testUserPassword;
        JCUsername     = 'ADMU_bind2';
        UpdateHomePath = $false
    }
}

$JCReversionHash = @{
    testCase1 = @{
        Description    = 'Reverse'
        Username       = 'ADMU_newUserInit';
        UserSID        = '';
        Password       = $testUserPassword;
        JCUsername     = 'ADMU_newUserInit2';
        UpdateHomePath = $true;

    }
}
$JCExistingHash = @{
    renameOriginalFiles = @{
        Description    = 'Existing'
        Username       = 'ADMU_ExistingUser';
        UserSID        = '';
        Password       = $testUserPassword;
        JCUsername     = 'ADMU_ADMU_ExistingUser2';
        UpdateHomePath = $false

    }
}