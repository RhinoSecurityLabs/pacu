# Pacu

Pacu is an open source AWS exploitation framework, designed for offensive security testing against cloud environments. Created and maintained by Rhino Security Labs, Pacu allows penetration testers to exploit configuration flaws within an AWS account, using modules to easily expand its functionality. Current modules enable a range of attacks, including user privilege escalation, backdooring of IAM users, attacking vulnerable Lambda functions, and much more.

## Installation

Pacu is a fairly lightweight program, as it requires only [Python3.5+](https://www.python.org/downloads/) and pip3 to install a handful of Python libraries. Running install.sh will check your Python version and ensure all Python packages are up to date.

## Quick Installation

```
  > git clone https://github.com/RhinoSecurityLabs/pacu
  > cd pacu
  > bash install.sh
  > python3 pacu.py
```

For a more detailed and user-friendly set of user instructions, please check out the Wiki's [installation guide](https://github.com/RhinoSecurityLabs/pacu/wiki/Installation).

## Key Features

* **Comprehensive AWS security-testing toolkit**, supported by a leading cybersecurity firm.
* **Wide range of powerful scanning and exploitation capabilities* offer by 36 modules (and counting)** which can be chained together.
* **Open-source and modular** structure allows easy auditing and community-driven improvement.

## Pacu's Modular Power

Pacu uses a range of [plug-in modules](https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Details) to assist an attacker in enumeration, privilege escalation, data exfiltration, service exploitation, and log manipulation within AWS environments. At present, Pacu has 36 modules for executing AWS attacks, but we'll be working hard to add more modules in the future, and suggestions for new modules (or even contributions of whole completed modules) are welcome.

In order to keep pace with ongoing AWS product developments, we've designed Pacu from the ground up with extensibility in mind. A common syntax and data structure keeps modules easy to build and expand on - no need to specify AWS regions or make redundant permission checks between modules.  A local SQLite database is used to manage and manipulate retrieved data, minimizing API calls (and associated logs). Reporting and attack auditing is also built into the framework; Pacu assists the documentation process through command logging and exporting, helping build a timeline for the testing process.

We'll be working on improve Pacu's core capabilities and building out a well-documented ecosystem so that cybersecurity researchers and developers can make new modules quickly and easily.

## Community

We're always happy to get bugs reports in the Pacu framework itself, as well as testing and feedback on different modules, and generally critical feedback to help refine the framework. We hope to see this grow into a key open-source tool for testing AWS security, and we need your help to make that happen! Any support towards this effort, through use and testing, improvement, or just by spreading the word, would be very much appreciated. If you have a feature request, an idea, or a bug to report, please [submit them here](https://github.com/RhinoSecurityLabs/pacu/issues/new?title=Briefly%20describe%20your%20idea%20or%20bug%20&body=Bug%20reports%3A%20please%20make%20sure%20to%20describe%20what%20happened%2C%20what%20you%20expected%20to%20happen%20instead%2C%20the%20steps%20that%20you%20took%20to%20trigger%20the%20bug%20(if%20any)%2C%20and%20provide%20any%20screenshots%20that%20you%20can.%20Error%20logs%20and%20sessions%20are%20also%20very%20helpful%2C%20but%20please%20make%20sure%20to%20remove%20any%20confidential%20information%20from%20them%20before%20upload.%0A%0AIdeas%20for%20new%20features%3A%20please%20provide%20as%20much%20detail%20as%20you%20can%2C%20including%20mockups%2C%20screenshots%2C%20pseduo-code%2C%20and%20most%20importantly%20why%20you%20think%20your%20idea%20would%20benefit%20Pacu.%0A%0ALastly%2C%20thank%20you%20-%20your%20contribution%20is%20appreciated!). Note that Pacu creates error logs within each session's folder, as well as a global error log for out-of-session errors which is created in the main directory. If you can, please include these logs with your bug reports, as it will dramatically simplify the debugging process.

If you're interested in contributing directly to the Pacu Framework itself, please read our [contribution guidelines](https://github.com/RhinoSecurityLabs/pacu/wiki/Contribution-Guidelines) for code conventions and git flow notes.

## Developing Pacu Modules

If you're interested in writing your own modules for Pacu, check out our [Module Development](https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Development-Guide) wiki page. As you develop new capabilities please reach out to us -- we'd love to add your new modules into the core collection that comes with Pacu.

## Pacu Framework Development Goals
  * Improve interface formatting
  * Database forward-migrations and version tracking
  * "Attack Playbooks" to allow for easier use of complex module execution chains
  * Colored console output
  * Module Dry-Run functionality
  * Allow use of standalone config files
  * Plugin architecture improvements

## Upcoming Pacu Modules

* PinPoint SMS/Email/Mobile Push Abuse
* S3 Item Interception
* And many more.

## Notes

* Pacu is officially supported in OSX and Linux.
* Pacu is Open-Source Software, and is distributed with a BSD-3-Clause License.

## Getting Started

The first time Pacu is launched, you will be prompted to start and name a new session. This session will be used to store AWS key pairs, as well as any data obtained from running various modules. You can have any number of different sessions in Pacu, each with their own sets of AWS keys and data, and resume a session at any time (though a restart is currently required to switch between sessions).

Modules require an AWS key, which grant you minimal access to an AWS environment and are comprised of an access key ID and a secret access key. To set your session's keys, use the `set_keys` command, and then follow the prompts to supply a key alias (nickname for reference), an AWS access key ID, an AWS secret access key, and an AWS session token (if you are using one).

If you are ever stuck, `help` will bring up a list of commands that are available.

For a more thorough tutorial, including some example attack paths to try out, please check out our [Quick-Start Guide](https://github.com/RhinoSecurityLabs/pacu/wiki/Quick-Start-Guide) on the wiki.

### Basic Commands in Pacu

* `list` will list the available modules for the regions that were set in the current session.
* `help module_name` will return the applicable help information for the specified module.
* `run module_name` will run the specified module with its default parameters.
* `run module_name --regions eu-west-1,us-west-1` will run the specified module against the eu-west-1 and us-west-1 regions (for modules that support the --regions argument)

### Module List

Pacu's capabilities will increase dramatically as the number of modules grows, as each module's findings are available for other modules to leverage during their own execution. Below is a summary list of the current modules in Pacu, but For a more thorough description of each module, please visit the [modules page](https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Details) on the wiki.

#### Unauthenticated Modules

- `s3_finder` - Enumerates/bruteforces S3 buckets based on different parameters.

#### Authenticated Modules

##### Recon Modules
- `confirm_permissions` - Tries to get a confirmed list of permissions for the current user.
- `download_ec2_userdata` - Downloads user data from EC2 instances.
- `enum_account` -  Enumerates concerning the account itself.
- `enum_codebuild` - Enumerates CodeBuild builds and projects while looking for sensitive data.
- `enum_ebs_volumes_snapshots` - Enumerates EBS volumes and snapshots and logs any without encryption.
- `enum_ec2` - Enumerates a ton of relevant EC2 info.
- `enum_ec2_termination_protection` - Collects a list of EC2 instances without termination protection.
- `enum_elb_logging` - Collects a list of Elastic Load Balancers without access logging.
- `enum_glue` - Enumerates Glue connections, crawlers, databases, development endpoints, and jobs.
- `enum_lambda` - Pulls data related to Lambda Functions, source code, aliases, event source mappings, versions, tags, and policies.
- `enum_lateral_movement` - Looks for Network Plane lateral movement opportunities.
- `enum_lightsail` - Examines Lightsail data fields and automatically enumerates them for all available regions.
- `enum_monitoring` - Detects monitoring and logging capabilities.
- `enum_permissions_bruteforce` - Enumerates permissions using brute force
- `enum_spend` - Enumerates account spend by service.
- `enum_users_roles_policies_groups` - Enumerates users, roles, customer-managed policies, and groups.
- `enum_waf` - Detects rules and rule groups for WAF.
- `get_credential_report` - Generates and downloads an IAM credential report.
- `inspector_report_fetcher` - Captures vulnerabilities found when running a preconfigured inspector report.
 - `s3_bucket_dump` - Enumerate and dumps files from S3 buckets.

##### Post Exploitation Modules
- `add_ec2_startup_sh_script` - Stops and restarts EC2 instances to execute code.
- `backdoor_ec2_sec_groups` - Adds backdoor rules to EC2 security groups.
- `cloudtrail_csv_injection` - Inject malicious formulas/data into CloudTrail event history.
- `create_api_gateway_keys` - Attempts to create an API gateway key for a (or all) rest APIs that are defined.
- `download_lightsail_ssh_keys` - Downloads Lightsails default SSH key pairs.
- `generate_lightsail_ssh_keys` - Creates SSH keys for available regions in AWS Lightsail.
- `generate_temp_lightsail_access` - Creates temporary SSH keys for available instances in AWS Lightsail.
- `sysman_ec2_rce` - Tries to execute code as root/SYSTEM on EC2 instances.

##### Escalation Modules
- `backdoor_assume_role` - Creates assume-role trust relationships between users and roles.
- `privesc_scan` - An IAM privilege escalation path finder and abuser.

##### Persistence Modules
- `backdoor_users_keys` - Adds API keys to other users.
- `backdoor_users_password` - Adds a password to users without one.

##### Logging Modules
- `dl_cloudtrail_event_history` - Downloads CloudTrail event history to JSON files.
- `dl_cloudwatch_logs` - Downloads CloudWatch logs within a specific time period to the session downloads directory.
- `disrupt_monitoring` - Disables, deletes, or minimizes various logging/monitoring services.

## Wiki

For walkthroughs and full documentation, please visit the [Pacu wiki](https://github.com/RhinoSecurityLabs/pacu/wiki).

## Contact Us

* We'd love to hear from you, whatever the reason. Shoot us an email at [pacu-beta@rhinosecuritylabs.com](mailto:pacu-beta@rhinosecuritylabs.com) anytime!

## Disclaimers, and the AWS Acceptable Use Policy

* To the best of our knowledge Pacu's capabilities are compliant with the AWS Acceptable Use Policy, but as a flexible and modular tool we cannot guarantee this will be true in every situation. It is entirely your responsibility to ensure that how you use Pacu is compliant with the AWS Acceptable Use Policy.
* Depending on what AWS services you use and what your planned testing entails, you may need to [request authorization from Amazon](https://aws.amazon.com/security/penetration-testing/) prior to actually running Pacu against your infrastructure. Determining whether or not such authorization is necessary is your responsibility.
* As with any penetration testing tool, it is your responsibility to get proper authorization before using Pacu outside of your own environment.
* Pacu is software that comes with absolutely no warranties whatsoever. By using Pacu, you take full responsibility for any and all outcomes that result.
