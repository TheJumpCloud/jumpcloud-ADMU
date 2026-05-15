# JumpCloud Active Directory Migration Utility

![ADMU overview](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/images/ADMU-landing.png)

The JumpCloud Active Directory Migration Utility (ADMU) migrates **Active Directory** or **Entra ID / Azure AD**–joined Windows users to **local accounts** so the [JumpCloud agent](https://jumpcloud.com/) can manage them. Domain accounts cannot be taken over directly by the agent; they must be converted to a local profile first. ADMU automates profile, registry, permissions, and optional domain-unbind / agent steps that would otherwise be manual.

## Documentation

Detailed guides, limitations, and troubleshooting live in the **[Wiki](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki)**. Good starting points:

| Topic                                                  | Wiki                                                                                                                                                                  |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Planning and first run                                 | [Getting Started](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Getting-Started)                                                                                |
| Tool Options + GUI                                     | [GUI Parameters](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/admu-gui)                                                                                        |
| Known constraints (certs, credentials, defaults, etc.) | [Limitations](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Limitations-of-User-Account-Conversion)                                                             |
| Logs and failures                                      | [Logging](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Logging), [Troubleshooting](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Troubleshooting-errors) |
| Remote migration (CLI, JumpCloud Commands, bulk)       | [Invoke admu from JumpCloud Agent](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Invoke-admu-from-jcagent)                                                      |

## Releases

- **GUI and CLI:** Download the latest build from **[Releases](https://github.com/TheJumpCloud/jumpcloud-ADMU/releases)**. Each release includes **`gui_jcadmu.exe`** (interactive GUI and CLI in one binary) and **`uwp_jcadmu.exe`**, which migration deploys into the Windows directory to fix UWP Appx package issues.

Only the `gui_jcadmu.exe` file is required for the ADMU, double click to run the GUI or pass parameters for scripted CLI use. The `uwp_jcadmu.exe` file is automatically downloaded and deployed into the Windows directory during migration to fix UWP Appx package issues.

## Support

Questions, bugs, and feature requests: **GitHub Issues** on this repository, [support@jumpcloud.com](mailto:support@jumpcloud.com), or the [feedback form](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Feedback-Form).

## License

This project is licensed under the [MIT License](./LICENSE).
