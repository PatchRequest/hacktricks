# PsExec/Winexec/ScExec

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

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** που υποστηρίζονται από τα **πιο προηγμένα** εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Πώς λειτουργούν

Η διαδικασία περιγράφεται στα παρακάτω βήματα, απεικονίζοντας πώς οι δυαδικοί κωδικοί υπηρεσιών χειρίζονται για να επιτευχθεί απομακρυσμένη εκτέλεση σε μια στοχευμένη μηχανή μέσω SMB:

1. **Αντιγραφή ενός δυαδικού κωδικού υπηρεσίας στο ADMIN$ share μέσω SMB** πραγματοποιείται.
2. **Δημιουργία μιας υπηρεσίας στη απομακρυσμένη μηχανή** γίνεται με την αναφορά στον δυαδικό κωδικό.
3. Η υπηρεσία **ξεκινά απομακρυσμένα**.
4. Με την έξοδο, η υπηρεσία **σταματά, και ο δυαδικός κωδικός διαγράφεται**.

### **Διαδικασία Χειροκίνητης Εκτέλεσης PsExec**

Υποθέτοντας ότι υπάρχει ένα εκτελέσιμο payload (δημιουργημένο με msfvenom και κρυμμένο χρησιμοποιώντας Veil για να αποφευχθεί η ανίχνευση από το antivirus), ονόματι 'met8888.exe', που αντιπροσωπεύει ένα payload meterpreter reverse_http, τα παρακάτω βήματα ακολουθούνται:

- **Αντιγραφή του δυαδικού κωδικού**: Ο εκτελέσιμος κωδικός αντιγράφεται στο ADMIN$ share από μια γραμμή εντολών, αν και μπορεί να τοποθετηθεί οπουδήποτε στο σύστημα αρχείων για να παραμείνει κρυμμένος.

- **Δημιουργία μιας υπηρεσίας**: Χρησιμοποιώντας την εντολή `sc` των Windows, η οποία επιτρέπει την αναζήτηση, δημιουργία και διαγραφή υπηρεσιών Windows απομακρυσμένα, δημιουργείται μια υπηρεσία ονόματι "meterpreter" που δείχνει στον ανεβασμένο δυαδικό κωδικό.

- **Έναρξη της υπηρεσίας**: Το τελευταίο βήμα περιλαμβάνει την εκκίνηση της υπηρεσίας, η οποία πιθανότατα θα έχει ως αποτέλεσμα ένα σφάλμα "time-out" λόγω του ότι ο δυαδικός κωδικός δεν είναι γνήσιος δυαδικός κωδικός υπηρεσίας και αποτυγχάνει να επιστρέψει τον αναμενόμενο κωδικό απόκρισης. Αυτό το σφάλμα είναι ασήμαντο καθώς ο κύριος στόχος είναι η εκτέλεση του δυαδικού κωδικού.

Η παρατήρηση του listener του Metasploit θα αποκαλύψει ότι η συνεδρία έχει ξεκινήσει επιτυχώς.

[Μάθετε περισσότερα για την εντολή `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Βρείτε πιο λεπτομερή βήματα στο: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Μπορείτε επίσης να χρησιμοποιήσετε τον δυαδικό κωδικό PsExec.exe των Windows Sysinternals:**

![](<../../.gitbook/assets/image (165).png>)

Μπορείτε επίσης να χρησιμοποιήσετε [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** που υποστηρίζονται από τα **πιο προηγμένα** εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
