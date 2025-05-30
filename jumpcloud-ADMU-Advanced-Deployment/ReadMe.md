# Remotely migrating AD users with the ADMU

It's possible to remotely migrate users with the ADMU PowerShell Module, in order to do this, devices will need some agent or credential set to execute code remotely. The JumpCloud ADMU is distributed as both a GUI exe and a PowerShell Module. Remote devices can call the function `Start-Migration` when the [JumpCloud.ADMU PowerShell module](https://www.powershellgallery.com/packages/JumpCloud.ADMU) is installed and migrate users from a single command. Installing the JumpCloud agent to devices is one such way to remotely execute this code on devices. With the JumpCloud agent installed remote commands can be executed on devices and the ADMU module can migrate individual users through a command template.

Please visit our [wiki page for detailed information](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/advanced-deployment-scenarios) on the two scripts required for remote migration using the JumpCloud Agent.
