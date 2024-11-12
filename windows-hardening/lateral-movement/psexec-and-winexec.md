# PsExec/Winexec/ScExec

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% embed url="https://websec.nl/" %}

## Πώς λειτουργούν

Η διαδικασία περιγράφεται στα παρακάτω βήματα, απεικονίζοντας πώς οι δυαδικοί κωδικοί υπηρεσιών χειρίζονται για να επιτευχθεί απομακρυσμένη εκτέλεση σε μια στοχοθετημένη μηχανή μέσω SMB:

1. **Αντιγραφή ενός δυαδικού κωδικού υπηρεσίας στο ADMIN$ share μέσω SMB** πραγματοποιείται.
2. **Δημιουργία μιας υπηρεσίας στη απομακρυσμένη μηχανή** γίνεται με την αναφορά στον δυαδικό κωδικό.
3. Η υπηρεσία **ξεκινά απομακρυσμένα**.
4. Με την έξοδο, η υπηρεσία **σταματά, και ο δυαδικός κωδικός διαγράφεται**.

### **Διαδικασία Χειροκίνητης Εκτέλεσης PsExec**

Υποθέτοντας ότι υπάρχει ένα εκτελέσιμο payload (δημιουργημένο με msfvenom και κρυμμένο χρησιμοποιώντας Veil για να αποφευχθεί η ανίχνευση από το antivirus), ονόματι 'met8888.exe', που αντιπροσωπεύει ένα payload reverse_http του meterpreter, ακολουθούνται τα εξής βήματα:

* **Αντιγραφή του δυαδικού κωδικού**: Ο εκτελέσιμος κωδικός αντιγράφεται στο ADMIN$ share από μια γραμμή εντολών, αν και μπορεί να τοποθετηθεί οπουδήποτε στο σύστημα αρχείων για να παραμείνει κρυμμένος.
* **Δημιουργία μιας υπηρεσίας**: Χρησιμοποιώντας την εντολή `sc` των Windows, η οποία επιτρέπει την αναζήτηση, δημιουργία και διαγραφή υπηρεσιών Windows απομακρυσμένα, δημιουργείται μια υπηρεσία ονόματι "meterpreter" που δείχνει στον ανεβασμένο δυαδικό κωδικό.
* **Έναρξη της υπηρεσίας**: Το τελευταίο βήμα περιλαμβάνει την εκκίνηση της υπηρεσίας, η οποία πιθανότατα θα έχει ως αποτέλεσμα ένα σφάλμα "time-out" λόγω του ότι ο δυαδικός κωδικός δεν είναι γνήσιος δυαδικός κωδικός υπηρεσίας και αποτυγχάνει να επιστρέψει τον αναμενόμενο κωδικό απόκρισης. Αυτό το σφάλμα είναι ασήμαντο καθώς ο κύριος στόχος είναι η εκτέλεση του δυαδικού κωδικού.

Η παρατήρηση του listener του Metasploit θα αποκαλύψει ότι η συνεδρία έχει ξεκινήσει επιτυχώς.

[Learn more about the `sc` command](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Find moe detailed steps in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Μπορείτε επίσης να χρησιμοποιήσετε τον δυαδικό κωδικό PsExec.exe των Windows Sysinternals:**

![](<../../.gitbook/assets/image (928).png>)

Μπορείτε επίσης να χρησιμοποιήσετε [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
