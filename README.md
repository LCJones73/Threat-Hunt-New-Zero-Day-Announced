# Threat Hunt New Zero Day Announced
A new ransomware strain named PwnCrypt has been reported in the news, highlighted in the daily briefing from _CyberWire Daily_. The CISO is concerned with the new ransomware strain being spread to the corporate network and wishes to investigate.

## 9:55 AM – News Breaks
Security news outlets report a new ransomware variant named PwnCrypt. The CISO is listening to _CyberWire Daily_ when he hears the followwing report:

"_You're listening to the CyberWire Network, powere by N2K. I'll be your host Dave Bittner. A joint advisory warns of .pwncrypt, a new ransomware strain said to be..._"

- Delivered via PowerShell
- Encrypting files with AES-256
- Targeting user directories like C:\Users\Public\Desktop
- Appending .pwncrypt to filenames (e.g., hello.txt → hello.pwncrypt.txt)
- The malware is also believed to be hosted on a public GitHub repository and executed using ExecutionPolicy Bypass.

The CISO is concerned as he thinks about the potential idea that ransomware could be present on their network, as Dave's voice trails off in the background. The CISO turns the podcast off and initiates an alert to his SecOps team.

## 10:00 AM – CISO Alert
The CISO sends out an internal threat bulletin to the SecOps team with the following key points:
- Search for executions of PowerShell scripts using -ExecutionPolicy Bypass
- Look for file events involving .pwncrypt.ps1
- Check for new file extensions .pwncrypt.*
- Review outbound web requests to raw GitHub URLs

### - Preparation
> [!NOTE]
> <strong>Set up the hunt by defining what you're looking for:</strong><BR><BR>
A new ransomware strain named PwnCrypt has been reported in the news, leveraging a PowerShell-based payload to encrypt files on infected systems. The payload, using AES-256 encryption, targets specific directories such as the C:\Users\Public\Desktop, encrypting files and prepending a .pwncrypt extension to the original extension. For example, hello.txt becomes hello.pwncrypt.txt after being targeted with the ransomware. The CISO is concerned with the new ransomware strain being spread to the corporate network and wishes to investigate.<BR><BR>
Activity: Develop a hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”).
The security program at the org is still immature and even lacks user training. It’s possible the newly discovered ransomware has made its way onto the corporate network. The hunt can be initiated based on the known IoCs (*.pwncrypt.* files)

### - Data Collection
> [!TIP]
> <strong>Gather relevant data from logs, network traffic, and endpoints.</strong><BR><BR>
Consider inspecting the file system as well as process activity for anything that matches the PwnCrypt IoCs<BR><BR>
Activity: Ensure data is available from all key sources for analysis.
Ensure the relevant tables contain recent logs:<br><br>
DeviceFileEvents<BR>
DeviceProcessEvents<BR>
> DeviceNetworkEvents

### - Data Analysis
> [!TIP]
> <strong>Analyze data to test your hypothesis.</strong><BR><BR>
Activity: Look for anomalies, patterns, or indicators of compromise (IOCs) using various tools and techniques.
  - Is there any evidence of the PwnCrypt ransomware being run? (files being created)
  - If so, can you identify the process and delivery method of the ransomware?

### - Investigation
> [!WARNING]
> <strong>Investigate any suspicious findings.</strong><BR><BR>
Activity: Dig deeper into detected threats, determine their scope, and escalate if necessary. See if anything you find matches TTPs within the MITRE ATT&CK Framework.
Search the DeviceFileEvents and DeviceProcessEvents tables around the same time based on your findings in the DeviceLogon Events.
### - Response
> [!WARNING]
> <strong>Mitigate any confirmed threats.</strong><BR><BR>
Activity: Work with security teams to contain, remove, and recover from the threat.
Can anything be done?
### - Documentation
> [!NOTE]
> <strong>Record your findings and learn from them.</strong><BR><BR>
Activity: Document what you found and use it to improve future hunts and defenses.
Document what you did
### - Improvement
> [!IMPORTANT]
> <strong>Improve your security posture or refine your methods for the next hunt.</strong><BR><BR>
Activity: Adjust strategies and tools based on what worked or didn’t.
Anything we could have done to prevent the thing we hunted for? Any way we could have improved our hunting process?

## Notes / Findings:

### Timeline Summary and Findings:

As the SecOps, we received the notification from the CISO. So we immediately check the logs in MS Defender to see if there is any evidence of .pwncrypt.

We use the following code to start our initial check:

![image](https://github.com/user-attachments/assets/00081378-dabc-4c6b-b1b8-949e3a62a7f8)

This yields us some unfortunate news, .pwncrypt is present on our network, specifically with a familiar DeviceName "vm-mde-cj"

![image](https://github.com/user-attachments/assets/1e723d48-ed45-4830-9768-069cbbb140c7)

You might be asking, what exactly does .pwncrypt do once installed, well let's break it down:

Why Is .pwncrypt Dangerous:
- **pwncrypt.ps1**: Name implies ransomware or encryption (pwn = slang for hacked, crypt = encryption).
- **programdata**: Legit but commonly used by malware to hide scripts or tools.
- **-ExecutionPolicy Bypass**: Frequently used in malware and red team tooling to avoid PowerShell security controls like Constrained Language Mode or ExecutionPolicy restrictions.

What This Likely Means:
- The file name is "pwncrypt" and the .ps1 is a clear indicator of compromise as a powershell script.
- A PowerShell script was either manually executed by a user or attacker or triggered via malware automation (e.g., scheduled task, malicious installer, registry key, startup folder).
- The script might download malware, encrypt files (ransomware), exfiltrate data, or establish persistence.

We're not out of the dark yet, all we've done is discover that a powershell script was run and it launched .pwncrypt onto our "Labuser" Device "vm-mde-cj"

Now we use the following code to discover how .pwncrypt got onto the system:

![image](https://github.com/user-attachments/assets/9b04068c-a501-4fdf-a842-564d93555420)

Which gave us the following results to further dig and investigate:

![image](https://github.com/user-attachments/assets/73a06ecd-89bb-4341-9e0b-4da8329771e7)

> [!NOTE]
> Typically you would not initially search using "_| where DeviceName == "vm-mde-cj"_" as part of this search. You might add it later if you're seeing other DeviceNames not having malicious indicators.

## Breaking This Down Further:

Take notice of the ProcessCommandLine has the Powershell.exe with the following ExecutionPolicy Bypass as mentioned earliern in our breakdown of what .pwncrypt is and how it functions.
You will also notice the same code is listed under InitiatingProcessCommandLine.

Now we need to see a timeline of events and uncover further how this Powershell code was initiated, using the following code:

![image](https://github.com/user-attachments/assets/17735816-3ab6-498d-bfe6-21d357334fee)

Which yielded our initial results to dig into and investigate:

![image](https://github.com/user-attachments/assets/32c30cf8-fc40-4656-95f6-e08f16edc42f)

Unfortunately it appears the Powershell code for .pwncrypt was initiated by "Labuser" on "vm-mde-cj".

Digging fuerther into the logs we see something interesting using the following code:

![image](https://github.com/user-attachments/assets/a9e3f848-d4f0-4938-b739-a678acdf307b)

And it yields the following results in our continued investigation of how this happened:

![image](https://github.com/user-attachments/assets/4b6a5d12-32ae-4fd0-9a2c-391e0ea21cda)

Unfortunately it is now clear that "Labuser" using "vm-mde-cj" initiated the Powershell .pwncrypt script intentionally.

Time to build out the story further going back to the beginning:

Timeline:
- We discovered that we have had a handful of older VMs that were potentially "Internet Facing"
- During our search we discovered one VM in particular was indeed "Internet Facing" - "wnx"
- We took that VM offline and issued a new one "vm-mde-test-cj" to "labuser" so that he was no longer using a compromised VM
- Then a week later we get wind that we are experiencing Network Degregation, potentially a Brute Froce attack
- As we investigate, to our surprise, "labuser" using "vm-mde-test-cj" was the culprit with malware using Powershell scripts
- Unfortunately after investigation and notifying HR, we decided to put "labuser" on a P.I.P.
- We once again provided a new VM "vm-mde-cj" to use
- During the HR meeting, labuser acted very unprofessional and eratic. We were worried due to their access level they may attempt something malicious.
- We investigated them looking for "Data Exfiltration", and fortunately for labuser, none was found. However, we did note the use of Powershell.
- Now we have discovered that labuser has indeed launched another Powershell code, clearly for malicious intent.
- We discovered a Powershell script that utilized .pwncrypt and either for Ransomware or to exfiltrate data like we were concerned about previously.

We will need to now take the following steps:

- Isolate VM (from Defender or Azure portal)
- Disable affected user accounts (e.g., labuser)
- Revoke any elevated credentials the malware may have captured

## But, we don't stop there and the story isn't over... yet.

We could continue to investigate the scope by doing the following:
- Check for file encryption
- Look for PowerShell execution of the ransomware
- Track downloaded scripts
- Finally, eradicate the threat
- Recovery is next from backups if available
- Prevention & Hardening:
  - Block Script Downloads
  - Change PowerShell Execution policy
  - Configure MS Defender Antivirus to detect .pwncrypt.ps1 via custom indicators or automated investigation
- Finally Documenting and reporting lessons learned through a timeline of events etc. 


## 11:15 AM – Response Initiated
- The VM is isolated in Defender
- labuser's account is disabled pending investigation
## Hunt queries are launched across the environment:
- Script name: pwncrypt.ps1
- File extension: .pwncrypt.
- Process command lines using: -ExecutionPolicy Bypass
- Network calls to GitHub raw URLs

Unfortunately, after all that we discovered with labuser, their employment was terminated. 

Luckily nothing was compromised to the level that it cost financial or other damages because of how efficient we performed our Threat Hunt.

Fortunately, we have a CISO that stays up to date on developments in the world of Cybersecurity listening to _CyberWire Daily_ when he heard about this New Zero Day.

### This concludes our Threat Hunt project scenarios. Keep in mind there is always a story to tell as you Threat Hunt and discover malicious activity on your network. Unfortunatley sometimes it is an insider threat!
