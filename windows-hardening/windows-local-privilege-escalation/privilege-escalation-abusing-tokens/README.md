# Κατάχρηση Διακριτικών

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

## Διακριτικά

Αν **δεν ξέρετε τι είναι τα Windows Access Tokens** διαβάστε αυτή τη σελίδα πριν συνεχίσετε:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Ίσως να μπορείτε να αναβαθμίσετε τα προνόμιά σας καταχρώντας τα διακριτικά που ήδη έχετε**

### SeImpersonatePrivilege

Αυτό είναι το προνόμιο που κατέχει οποιαδήποτε διαδικασία που επιτρέπει την προσποίηση (αλλά όχι τη δημιουργία) οποιουδήποτε διακριτικού, εφόσον μπορεί να αποκτηθεί μια αναφορά σε αυτό. Ένα προνομιακό διακριτικό μπορεί να αποκτηθεί από μια υπηρεσία Windows (DCOM) προκαλώντας την να εκτελέσει NTLM authentication κατά ενός exploit, επιτρέποντας στη συνέχεια την εκτέλεση μιας διαδικασίας με προνόμια SYSTEM. Αυτή η ευπάθεια μπορεί να εκμεταλλευτεί χρησιμοποιώντας διάφορα εργαλεία, όπως [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (το οποίο απαιτεί να είναι απενεργοποιημένο το winrm), [SweetPotato](https://github.com/CCob/SweetPotato), [EfsPotato](https://github.com/zcgonvh/EfsPotato), [DCOMPotato](https://github.com/zcgonvh/DCOMPotato) και [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Είναι πολύ παρόμοιο με το **SeImpersonatePrivilege**, θα χρησιμοποιήσει την **ίδια μέθοδο** για να αποκτήσει ένα προνομιακό διακριτικό.\
Στη συνέχεια, αυτό το προνόμιο επιτρέπει **να αναθέσει ένα πρωτεύον διακριτικό** σε μια νέα/ανασταλμένη διαδικασία. Με το προνομιακό διακριτικό προσποίησης μπορείτε να παράγετε ένα πρωτεύον διακριτικό (DuplicateTokenEx).\
Με το διακριτικό, μπορείτε να δημιουργήσετε μια **νέα διαδικασία** με 'CreateProcessAsUser' ή να δημιουργήσετε μια διαδικασία ανασταλμένη και **να ορίσετε το διακριτικό** (γενικά, δεν μπορείτε να τροποποιήσετε το πρωτεύον διακριτικό μιας εκτελούμενης διαδικασίας).

### SeTcbPrivilege

Αν έχετε ενεργοποιήσει αυτό το διακριτικό μπορείτε να χρησιμοποιήσετε **KERB\_S4U\_LOGON** για να αποκτήσετε ένα **διακριτικό προσποίησης** για οποιονδήποτε άλλο χρήστη χωρίς να γνωρίζετε τα διαπιστευτήρια, **να προσθέσετε μια αυθαίρετη ομάδα** (admins) στο διακριτικό, να ορίσετε το **επίπεδο ακεραιότητας** του διακριτικού σε "**medium**", και να αναθέσετε αυτό το διακριτικό στο **τρέχον νήμα** (SetThreadToken).

### SeBackupPrivilege

Το σύστημα προκαλεί να **παρέχει πλήρη πρόσβαση** ανάγνωσης σε οποιοδήποτε αρχείο (περιορισμένο σε λειτουργίες ανάγνωσης) μέσω αυτού του προνομίου. Χρησιμοποιείται για **ανάγνωση των κατακερματισμών κωδικών πρόσβασης των τοπικών λογαριασμών Διαχειριστή** από τη μητρώο, ακολουθούμενη από τη χρήση εργαλείων όπως το "**psexec**" ή το "**wmiexec**" με τον κατακερματισμό (τεχνική Pass-the-Hash). Ωστόσο, αυτή η τεχνική αποτυγχάνει υπό δύο συνθήκες: όταν ο λογαριασμός Τοπικού Διαχειριστή είναι απενεργοποιημένος, ή όταν υπάρχει πολιτική που αφαιρεί τα διοικητικά δικαιώματα από τους Τοπικούς Διαχειριστές που συνδέονται απομακρυσμένα.\
Μπορείτε να **καταχραστείτε αυτό το προνόμιο** με:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* ακολουθώντας τον **IppSec** στο [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Ή όπως εξηγείται στην ενότητα **αναβάθμιση προνομίων με Backup Operators**:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Η άδεια για **πρόσβαση εγγραφής** σε οποιοδήποτε αρχείο συστήματος, ανεξαρτήτως της Λίστας Ελέγχου Πρόσβασης (ACL) του αρχείου, παρέχεται από αυτό το προνόμιο. Ανοίγει πολλές δυνατότητες για αναβάθμιση, συμπεριλαμβανομένης της δυνατότητας **τροποποίησης υπηρεσιών**, εκτέλεσης DLL Hijacking και ρύθμισης **debuggers** μέσω των Επιλογών Εκτέλεσης Αρχείων Εικόνας μεταξύ άλλων τεχνικών.

### SeCreateTokenPrivilege

Το SeCreateTokenPrivilege είναι μια ισχυρή άδεια, ιδιαίτερα χρήσιμη όταν ένας χρήστης έχει τη δυνατότητα να προσποιείται διακριτικά, αλλά και στην απουσία του SeImpersonatePrivilege. Αυτή η ικανότητα εξαρτάται από την ικανότητα να προσποιείται ένα διακριτικό που αντιπροσωπεύει τον ίδιο χρήστη και του οποίου το επίπεδο ακεραιότητας δεν υπερβαίνει αυτό της τρέχουσας διαδικασίας.

**Κύρια Σημεία:**
- **Προσποίηση χωρίς SeImpersonatePrivilege:** Είναι δυνατόν να αξιοποιηθεί το SeCreateTokenPrivilege για EoP προσποιούμενοι διακριτικά υπό συγκεκριμένες συνθήκες.
- **Συνθήκες για Προσποίηση Διακριτικών:** Η επιτυχής προσποίηση απαιτεί το διακριτικό στόχο να ανήκει στον ίδιο χρήστη και να έχει επίπεδο ακεραιότητας που είναι μικρότερο ή ίσο με το επίπεδο ακεραιότητας της διαδικασίας που προσπαθεί να προσποιηθεί.
- **Δημιουργία και Τροποποίηση Διακριτικών Προσποίησης:** Οι χρήστες μπορούν να δημιουργήσουν ένα διακριτικό προσποίησης και να το ενισχύσουν προσθέτοντας ένα SID (Αναγνωριστικό Ασφαλείας) προνομιακής ομάδας.

### SeLoadDriverPrivilege

Αυτό το προνόμιο επιτρέπει τη **φόρτωση και εκφόρτωση οδηγών συσκευών** με τη δημιουργία μιας καταχώρισης μητρώου με συγκεκριμένες τιμές για το `ImagePath` και το `Type`. Δεδομένου ότι η άμεση πρόσβαση εγγραφής στο `HKLM` (HKEY_LOCAL_MACHINE) είναι περιορισμένη, πρέπει να χρησιμοποιηθεί το `HKCU` (HKEY_CURRENT_USER). Ωστόσο, για να γίνει το `HKCU` αναγνωρίσιμο από τον πυρήνα για τη ρύθμιση του οδηγού, πρέπει να ακολουθηθεί μια συγκεκριμένη διαδρομή.

Αυτή η διαδρομή είναι `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, όπου `<RID>` είναι ο Σχετικός Αναγνωριστής του τρέχοντος χρήστη. Μέσα στο `HKCU`, πρέπει να δημιουργηθεί αυτή η ολόκληρη διαδρομή και να οριστούν δύο τιμές:
- `ImagePath`, που είναι η διαδρομή προς το δυαδικό που θα εκτελεστεί
- `Type`, με τιμή `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Βήματα που πρέπει να ακολουθηθούν:**
1. Πρόσβαση στο `HKCU` αντί για `HKLM` λόγω περιορισμένης πρόσβασης εγγραφής.
2. Δημιουργία της διαδρομής `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` εντός του `HKCU`, όπου `<RID>` αντιπροσωπεύει τον Σχετικό Αναγνωριστή του τρέχοντος χρήστη.
3. Ορισμός του `ImagePath` στη διαδρομή εκτέλεσης του δυαδικού.
4. Ανάθεση του `Type` ως `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Περισσότεροι τρόποι για να καταχραστεί αυτή η προνομία στο [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε μια διαδικασία να **αναλάβει την ιδιοκτησία ενός αντικειμένου**, παρακάμπτοντας την απαίτηση για ρητή διακριτική πρόσβαση μέσω της παροχής δικαιωμάτων πρόσβασης WRITE_OWNER. Η διαδικασία περιλαμβάνει πρώτα την εξασφάλιση της ιδιοκτησίας του προοριζόμενου κλειδιού μητρώου για σκοπούς εγγραφής, και στη συνέχεια την τροποποίηση του DACL για να επιτραπούν οι λειτουργίες εγγραφής.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Αυτό το προνόμιο επιτρέπει την **αποσφαλμάτωση άλλων διεργασιών**, συμπεριλαμβανομένης της ανάγνωσης και εγγραφής στη μνήμη. Διάφορες στρατηγικές για την ένεση μνήμης, ικανές να παρακάμψουν τις περισσότερες λύσεις antivirus και πρόληψης εισβολών φιλοξενίας, μπορούν να χρησιμοποιηθούν με αυτό το προνόμιο.

#### Dump memory

Μπορείτε να χρησιμοποιήσετε το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **καταγράψετε τη μνήμη μιας διεργασίας**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στη διεργασία **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, η οποία είναι υπεύθυνη για την αποθήκευση των διαπιστευτηρίων χρηστών μόλις ένας χρήστης έχει συνδεθεί επιτυχώς σε ένα σύστημα.

Μπορείτε στη συνέχεια να φορτώσετε αυτό το dump στο mimikatz για να αποκτήσετε κωδικούς πρόσβασης:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Αν θέλετε να αποκτήσετε ένα `NT SYSTEM` shell μπορείτε να χρησιμοποιήσετε:

* ****[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)****
* ****[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Το `SeManageVolumePrivilege` είναι ένα δικαίωμα χρήστη των Windows που επιτρέπει στους χρήστες να διαχειρίζονται δίσκους, συμπεριλαμβανομένης της δημιουργίας και διαγραφής τους. Ενώ προορίζεται για διαχειριστές, αν παραχωρηθεί σε μη διαχειριστές χρήστες, μπορεί να εκμεταλλευτεί για αναβάθμιση δικαιωμάτων.

Είναι δυνατόν να εκμεταλλευτεί αυτό το δικαίωμα για να χειριστεί δίσκους, οδηγώντας σε πλήρη πρόσβαση σε δίσκους. Το [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) μπορεί να χρησιμοποιηθεί για να δώσει πλήρη πρόσβαση σε όλους τους χρήστες για το C:\

Επιπλέον, η διαδικασία που περιγράφεται σε [αυτό το άρθρο του Medium](https://medium.com/@raphaeltzy13/exploiting-semanagevolumeprivilege-with-dll-hijacking-windows-privilege-escalation-1a4f28372d37) περιγράφει τη χρήση DLL hijacking σε συνδυασμό με το `SeManageVolumePrivilege` για την αναβάθμιση δικαιωμάτων. Τοποθετώντας ένα payload DLL `C:\Windows\System32\wbem\tzres.dll` και καλώντας το `systeminfo`, η dll εκτελείται.

## Check privileges
```
whoami /priv
```
Τα **tokens που εμφανίζονται ως Απενεργοποιημένα** μπορούν να ενεργοποιηθούν, μπορείτε πραγματικά να εκμεταλλευτείτε τα _Ενεργοποιημένα_ και _Απενεργοποιημένα_ tokens.

### Ενεργοποίηση Όλων των tokens

Αν έχετε tokens που είναι απενεργοποιημένα, μπορείτε να χρησιμοποιήσετε το σενάριο [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσετε όλα τα tokens:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embed in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Θα επέτρεπε σε έναν χρήστη να προσποιείται tokens και να αποκτά δικαιώματα στο nt system χρησιμοποιώντας εργαλεία όπως το potato.exe, rottenpotato.exe και juicypotato.exe"_                                                                                                                                                                   | Ευχαριστώ [Aurélien Chalot](https://twitter.com/Defte\_) για την ενημέρωση. Θα προσπαθήσω να το ξαναδιατυπώσω σε κάτι πιο συνταγές σύντομα.                                                                                                                                                                                        |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Διαβάστε ευαίσθητα αρχεία με `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Μπορεί να είναι πιο ενδιαφέρον αν μπορείτε να διαβάσετε το %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (και robocopy) δεν είναι χρήσιμο όταν πρόκειται για ανοιχτά αρχεία.<br><br>- Το Robocopy απαιτεί τόσο το SeBackup όσο και το SeRestore για να λειτουργήσει με την παράμετρο /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Δημιουργήστε αυθαίρετο token που περιλαμβάνει δικαιώματα τοπικού διαχειριστή με `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Διπλασιάστε το token του `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Το σενάριο μπορεί να βρεθεί στο [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Φορτώστε ελαττωματικό kernel driver όπως το <code>szkg64.sys</code><br>2. Εκμεταλλευτείτε την ευπάθεια του driver<br><br>Εναλλακτικά, το δικαίωμα μπορεί να χρησιμοποιηθεί για να ξεφορτωθείτε drivers που σχετίζονται με την ασφάλεια με την εντολή <code>ftlMC</code> builtin. δηλαδή: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Η ευπάθεια του <code>szkg64</code> αναφέρεται ως <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Ο <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">κωδικός εκμετάλλευσης</a> δημιουργήθηκε από <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Εκκινήστε το PowerShell/ISE με το δικαίωμα SeRestore παρόν.<br>2. Ενεργοποιήστε το δικαίωμα με <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Μετονομάστε το utilman.exe σε utilman.old<br>4. Μετονομάστε το cmd.exe σε utilman.exe<br>5. Κλειδώστε την κονσόλα και πατήστε Win+U</p> | <p>Η επίθεση μπορεί να ανιχνευθεί από κάποιο λογισμικό AV.</p><p>Η εναλλακτική μέθοδος βασίζεται στην αντικατάσταση των δυαδικών αρχείων υπηρεσιών που αποθηκεύονται στα "Program Files" χρησιμοποιώντας το ίδιο δικαίωμα</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Μετονομάστε το cmd.exe σε utilman.exe<br>4. Κλειδώστε την κονσόλα και πατήστε Win+U</p>                                                                                                                                       | <p>Η επίθεση μπορεί να ανιχνευθεί από κάποιο λογισμικό AV.</p><p>Η εναλλακτική μέθοδος βασίζεται στην αντικατάσταση των δυαδικών αρχείων υπηρεσιών που αποθηκεύονται στα "Program Files" χρησιμοποιώντας το ίδιο δικαίωμα.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

* Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) about privesc with tokens.

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
