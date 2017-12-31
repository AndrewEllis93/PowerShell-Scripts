# PowerShell Scripts
Please read the header descriptions and comments in each script body, some contain important instructions or warnings.

**ADHealthCheck:** This one is largely based on a script by Vikas Sukhija, who is credited in the body. I really only made some minor edits to his. Mine just adds a column that shows the last replication time and only emails if there is an unhealthy status or failure to cut down on email spam.

**Disable-InactiveADAccounts:** Make sure you read through the comments (as with all of these scripts). It just finds the last logon for all AD accounts and disables any that have been inactive for X number of days (depending on what threshold you set). The difference with this script is that it gets the most accurate last logon available by comparing the results from all domain controllers. By default the lastlogontimestamp is only replicated every 14 days minus a random percentage of 5. This makes it much more accurate. It also supports AD exclusion groups (you can specify more than one) that allow you to exclude things like service accounts. It exports CSVs and sends an email report to the specified recipients.

**Discover-DriveSpace:** This one gets all your servers in AD and dumps the drives with sizes and remaining free space to a CSV (drivespace.csv). It also export some other files - pingable.txt, pingfail.txt, and servers.csv. Those should be self-explanatory.

**Discover-Shares:** This one is a discovery function to find all Windows shares on the domain. Useful for acquisitions.

**Dump-GPOs:** This one exports all of your GPOs' HTML reports, a CSV detailing all the GPO links, and a txt list of all the GPOs.

**Enumerate-Access:** This function will spit back all of the permissions of a specified folder, recursively. You can choose to return inherited permissions or not. I wrote this specifically to show each and every ACL entry on a separate line. It's really useful for finding where a group or user is being used in NTFS ACLs. This helped us get rid of mail-enabled security groups by discovering each place that they were being used in NTFS ACLs so we could replace them. In most cases you won't want it to return inherited permissions (it doesn't by default) so you don't get a TON of redundant output, just the explicit ACL entries. It will generate a lot of disk activity on the target server because it scans the entire file system of the folder specified. At one point I actually combined this with the Find-Shares script to enumerate the ACLs on every file share we had. It took forever, needless to say, but helped a lot with weeding out old AD groups :)

**Move Disabled:** This moves disabled users and computers, but instead of just moving them to a single OU, it rounds them up and ages them through different OUs (0-30 days, 30-180 days, over 180 days). It uses ExtensionAttribute3 to stamp the user/computer accounts with the disable date and notes the original OU in the description/info fields. Make sure you are NOT using ExtensionAttribute3 for anything else before running. Supports "-ReportOnly" argument (basically WhatIf). This is intended to be run daily. It also supports being used in conjunction with Disable-InactiveADAccounts.

**Move-StaleUserFolders:** This script will scan all first-level sub-folders of the specified BasePath to find the most recent LastWriteTime in each one (recursively). This is really intended for user folders. It will move stale folders to the directory specified. You can modify this to just report instead, read the description up top.

**Restart-DFSRAndEnableAutoRecovery:** Nice and short and simple. It restarts the DFSR service on all domain controllers (I schedule this to run nightly. This isn't really necessary but I have found it to prevent some misc issues that crop up once in a blue moon) and enables DFSR auto-recovery, which for whatever reason is disabled on domain controllers by default.

**Send-PasswordNotices:** This sends password expiration notice emails to users at 1,2,3,7, and 14 days. Supports an AD exclusion group.







