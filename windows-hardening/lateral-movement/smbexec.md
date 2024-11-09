# SmbExec/ScExec

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

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Αποκτήστε την προοπτική ενός χάκερ για τις εφαρμογές σας, το δίκτυο και το cloud**

**Βρείτε και αναφέρετε κρίσιμες, εκμεταλλεύσιμες ευπάθειες με πραγματικό επιχειρηματικό αντίκτυπο.** Χρησιμοποιήστε τα 20+ προσαρμοσμένα εργαλεία μας για να χαρτογραφήσετε την επιφάνεια επίθεσης, να βρείτε ζητήματα ασφαλείας που σας επιτρέπουν να κλιμακώσετε τα δικαιώματα και να χρησιμοποιήσετε αυτοματοποιημένες εκμεταλλεύσεις για να συλλέξετε βασικά αποδεικτικά στοιχεία, μετατρέποντας τη σκληρή σας δουλειά σε πειστικές αναφορές.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Πώς Λειτουργεί

**Smbexec** είναι ένα εργαλείο που χρησιμοποιείται για την απομακρυσμένη εκτέλεση εντολών σε συστήματα Windows, παρόμοιο με το **Psexec**, αλλά αποφεύγει να τοποθετήσει οποιαδήποτε κακόβουλα αρχεία στο σύστημα-στόχο.

### Κύρια Σημεία σχετικά με το **SMBExec**

- Λειτουργεί δημιουργώντας μια προσωρινή υπηρεσία (για παράδειγμα, "BTOBTO") στη μηχανή-στόχο για να εκτελεί εντολές μέσω του cmd.exe (%COMSPEC%), χωρίς να ρίχνει κανένα δυαδικό αρχείο.
- Παρά την κρυφή του προσέγγιση, δημιουργεί αρχεία καταγραφής γεγονότων για κάθε εντολή που εκτελείται, προσφέροντας μια μορφή μη διαδραστικού "shell".
- Η εντολή για σύνδεση χρησιμοποιώντας το **Smbexec** μοιάζει με αυτό:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Εκτέλεση Εντολών Χωρίς Δυαδικά

- **Smbexec** επιτρέπει την άμεση εκτέλεση εντολών μέσω των binPaths υπηρεσίας, εξαλείφοντας την ανάγκη για φυσικά δυαδικά στον στόχο.
- Αυτή η μέθοδος είναι χρήσιμη για την εκτέλεση εντολών μίας φοράς σε έναν στόχο Windows. Για παράδειγμα, η σύνδεση της με το module `web_delivery` του Metasploit επιτρέπει την εκτέλεση ενός PowerShell-στοχευμένου αντίστροφου payload Meterpreter.
- Δημιουργώντας μια απομακρυσμένη υπηρεσία στη μηχανή του επιτιθέμενου με το binPath ρυθμισμένο να εκτελεί την παρεχόμενη εντολή μέσω του cmd.exe, είναι δυνατό να εκτελεστεί το payload με επιτυχία, επιτυγχάνοντας callback και εκτέλεση payload με τον listener του Metasploit, ακόμη και αν προκύψουν σφάλματα απόκρισης υπηρεσίας.

### Παράδειγμα Εντολών

Η δημιουργία και εκκίνηση της υπηρεσίας μπορεί να επιτευχθεί με τις παρακάτω εντολές:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Αποκτήστε την προοπτική ενός χάκερ για τις διαδικτυακές σας εφαρμογές, το δίκτυο και το cloud**

**Βρείτε και αναφέρετε κρίσιμες, εκμεταλλεύσιμες ευπάθειες με πραγματικό επιχειρηματικό αντίκτυπο.** Χρησιμοποιήστε τα 20+ προσαρμοσμένα εργαλεία μας για να χαρτογραφήσετε την επιφάνεια επίθεσης, να βρείτε ζητήματα ασφαλείας που σας επιτρέπουν να κλιμακώσετε προνόμια και να χρησιμοποιήσετε αυτοματοποιημένα exploits για να συλλέξετε βασικά αποδεικτικά στοιχεία, μετατρέποντας τη σκληρή σας δουλειά σε πειστικές αναφορές.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

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
