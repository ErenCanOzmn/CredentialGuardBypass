#CredentialGuardBypass – Bypassing Credential Guard via LSASS Memory Manipulation
This project demonstrates a technique to bypass Microsoft Credential Guard by directly manipulating memory structures within the lsass.exe process.

##Overview
Credential Guard is a security feature introduced by Microsoft that uses Virtualization-Based Security (VBS) to protect credentials from being stolen, even by attackers with administrative privileges. It does so by isolating LSASS and storing secrets (such as password hashes) in a protected virtual environment.

![image](https://github.com/user-attachments/assets/ef7b3764-67ed-4a9d-898b-4342e1ec94d0)


###However, if an attacker already has SYSTEM-level access, it's possible to:
Locate specific memory structures related to credential handling in LSASS,
Patch flags such as UseLogonCredential and IsCredGuardEnabled directly in memory,
Trigger the system to treat LSASS as if Credential Guard were not active,
Extract cleartext credentials on subsequent logins.

###This repo includes:
Methods for obtaining a handle to LSASS using NtQuery/NtOpen APIs
Signature scanning within wdigest.dll to locate offset values
How to calculate virtual addresses for targeted variables
Patch process for changing values in LSASS memory
Demonstration of cleartext credential recovery post-manipulation

###Requirements
SYSTEM privileges (e.g., via SeDebugPrivilege or kernel exploit) - By default local admin users have these.

##Example
This section demonstrates the process of bypassing Credential Guard by manipulating LSASS memory directly.

1. Initial Flag Values in LSASS Memory
The UseLogonCredential and IsCredGuardEnabled flags initially show:

UseLogonCredential = 0
IsCredGuardEnabled = 1

2. Checking Current LSASS Memory State
Using the tool dizmana_credguard.exe, the current values of these flags are verified:

powershell .\dizmana_credguard.exe check

![image](https://github.com/user-attachments/assets/aea4f76e-218f-4c3f-a75b-c1b16575698a)


3. Patching LSASS Memory
The values are patched in memory to:

UseLogonCredential = 1
IsCredGuardEnabled = 0

![image](https://github.com/user-attachments/assets/cbc5750c-304e-4597-b7e6-57251b0ae7da)

4. Credential Dumping via Mimikatz
After patching and re-authentication, cleartext passwords become visible in memory and can be extracted using tools like Mimikatz.

![image](https://github.com/user-attachments/assets/d8f533e4-d085-481c-bd8e-13a2bc55f904)



