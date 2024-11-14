# DPAPI: "Key not valid for use in specified state." (NTE_BAD_KEY_STATE)

There has been a lot of writeups about the classic DPAPI. There are two functions `CryptProtectData` and `CryptUnprotectData` which basically make up the whole of the _classic_ DPAPI. Under the hood it uses the classic Crypto API (CAPI) and basically is closely related to the functionality of the following two functions:

* `RtlEncryptMemory` (== `advapi32!SystemFunction040`)
* `RtlDecryptMemory` (== `advapi32!SystemFunction041`)

 `System.Security.Cryptography.ProtectedData.ProtectOrUnprotect` and `System.Security.Cryptography.ProtectedData.Unprotect` from .NET uses the classic DPAPI (`CryptProtectData` and `CryptUnprotectData`).

 The main point is that one can protect secrets based on the machine or the user. For the user they're stored in `%AppData%\Microsoft\Protect\` (with Windows Explorer you can alternatively navigate to `shell:DpAPIKeys`). So clearly that part depends on the user profile being loaded and available.

 Inside the `Protect` directory there is a file called `credhist` and a subdirectory named after the user's SID. In the latter there are files with a GUID as their name and a single `Preferred` file that denotes the latest master key in the chain of master keys that _should_ be stored in `credhist`. This repo is about the case where the `credhist` file never gets updated and the master-key generation gets triggered every fews hours.

Additionally since around Windows 8 there is a so-called CNG DPAPI (aka DPAPI NG) which is based on CryptoNG (CNG) and aside from providing a small project attempting to observe the amnesic DPAPI state it attempts to ascertain if DPAPI NG is a suitable replacement for the classic DPAPI. I.e. does it follow from the classic DPAPI being in an amnesic state that the DPAPI NG also ends up in that state?

## Related

* [An investigation by Tavis Ormandy regarding an issue caused by S4U logon type scheduled tasks](https://bugs.chromium.org/p/chromium/issues/detail?id=1069383#c90)  
  ```
  Get-ScheduledTask | %{ If ($_.Principal.LogonType -eq 'S4U') { $_ } }
  ```  
  Of note (since a correlation to locking/unlocking was also found in our case):  
  > I think the problem is in the dpapisrv cache, maybe a lock is not being released. I wonder if Microsoft made some changes to it recently?
  > I forgot to mention that there is an easy way to trigger this bug, at least after it has happened the first time:
  > 1. Close Chrome. Wait until there are no more "chrome.exe" instances in the Task Manager.
  > 2. Press WIN+L to lock the PC.
  > 3. Log in again.
  > 4. Open Chrome. Every cookie will be lost and errors will appear in the Event Viewer.
  * `chrome://histograms/OSCrypt` was introduced due to the observations from this ticket
* [Windows 10 2004/20H2 and the broken 'Credentials Manager': Root Cause and Workaround – Part 1](https://borncity.com/win/2020/11/09/windows-10-2004-20h2-und-der-kaputte-credentials-manager-ursache-und-workaround/)
* [Windows 10 2004/20H2 and the broken 'Credentials Manager': Cause and Workaround – Part 2](https://borncity.com/win/2020/11/10/windows-10-2004-20h2-und-der-kaputte-credentials-manager-ursache-und-workaround-teil-2/)
* [Systemwide password amnesia (v2004 build 19041.173) ](https://answers.microsoft.com/en-us/windows/forum/all/systemwide-password-amnesia-v2004-build-19041173/232381f8-e2c6-4e8a-b01c-712fceb0e39e)
* [February 2, 2021 -- KB4598291 (OS Builds 19041.789 and 19042.789)](https://support.microsoft.com/en-us/topic/february-2-2021-kb4598291-os-builds-19041-789-and-19042-789-preview-6a766199-a4f1-616e-1f5c-58bdc3ca5e3b)
  * "Addresses an issue in which using local Service for User (S4U) affects Data Protection API (DPAPI) credential keys and causes users to sign out unexpectedly."

### Writeups

* https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf
* https://tierzerosecurity.co.nz/2024/01/22/data-protection-windows-api.html
* https://github.com/rxwx/chlonium

## Support tickets with Microsoft

* 2208300040004683 (closed, they claimed it was the wrong division it ended up with)
* 2210040060000363 (closed in late 2024, succeeded by the one below)
* 2410070050003494