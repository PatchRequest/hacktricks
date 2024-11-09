# Linux Active Directory

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

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

Μια μηχανή linux μπορεί επίσης να είναι παρούσα μέσα σε ένα περιβάλλον Active Directory.

Μια μηχανή linux σε ένα AD μπορεί να **αποθηκεύει διάφορα CCACHE tickets μέσα σε αρχεία. Αυτά τα tickets μπορούν να χρησιμοποιηθούν και να κακοποιηθούν όπως οποιοδήποτε άλλο kerberos ticket**. Για να διαβάσετε αυτά τα tickets θα χρειαστεί να είστε ο χρήστης κάτοχος του ticket ή **root** μέσα στη μηχανή.

## Enumeration

### AD enumeration από linux

Αν έχετε πρόσβαση σε ένα AD σε linux (ή bash σε Windows) μπορείτε να δοκιμάσετε [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) για να καταγράψετε το AD.

Μπορείτε επίσης να ελέγξετε την παρακάτω σελίδα για να μάθετε **άλλους τρόπους για να καταγράψετε το AD από linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

Το FreeIPA είναι μια ανοιχτού κώδικα **εναλλακτική** λύση για το Microsoft Windows **Active Directory**, κυρίως για **Unix** περιβάλλοντα. Συνδυάζει έναν πλήρη **LDAP κατάλογο** με ένα MIT **Kerberos** Key Distribution Center για διαχείριση παρόμοια με το Active Directory. Χρησιμοποιεί το Dogtag **Certificate System** για τη διαχείριση πιστοποιητικών CA & RA, υποστηρίζει **πολλαπλούς παράγοντες** αυθεντικοποίησης, συμπεριλαμβανομένων των smartcards. Το SSSD είναι ενσωματωμένο για διαδικασίες αυθεντικοποίησης Unix. Μάθετε περισσότερα γι' αυτό στην:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Παίζοντας με τα tickets

### Pass The Ticket

Σε αυτή τη σελίδα θα βρείτε διάφορες τοποθεσίες όπου μπορείτε να **βρείτε kerberos tickets μέσα σε έναν host linux**, στην επόμενη σελίδα μπορείτε να μάθετε πώς να μετατρέψετε αυτά τα CCache tickets σε μορφές Kirbi (τη μορφή που χρειάζεστε να χρησιμοποιήσετε σε Windows) και επίσης πώς να εκτελέσετε μια επίθεση PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### CCACHE ticket reuse από /tmp

Τα αρχεία CCACHE είναι δυαδικές μορφές για **αποθήκευση πιστοποιητικών Kerberos** που συνήθως αποθηκεύονται με δικαιώματα 600 στο `/tmp`. Αυτά τα αρχεία μπορούν να αναγνωριστούν από τη **μορφή ονόματος τους, `krb5cc_%{uid}`,** που σχετίζεται με το UID του χρήστη. Για την επαλήθευση του ticket αυθεντικοποίησης, η **μεταβλητή περιβάλλοντος `KRB5CCNAME`** θα πρέπει να οριστεί στη διαδρομή του επιθυμητού αρχείου ticket, επιτρέποντας την επαναχρησιμοποίησή του.

Λίστα με το τρέχον ticket που χρησιμοποιείται για αυθεντικοποίηση με `env | grep KRB5CCNAME`. Η μορφή είναι φορητή και το ticket μπορεί να **επανχρησιμοποιηθεί ορίζοντας τη μεταβλητή περιβάλλοντος** με `export KRB5CCNAME=/tmp/ticket.ccache`. Η μορφή ονόματος του ticket Kerberos είναι `krb5cc_%{uid}` όπου uid είναι το UID του χρήστη.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE ticket reuse from keyring

**Τα αποθηκευμένα Kerberos tickets στη μνήμη μιας διαδικασίας μπορούν να εξαχθούν**, ιδιαίτερα όταν η προστασία ptrace της μηχανής είναι απενεργοποιημένη (`/proc/sys/kernel/yama/ptrace_scope`). Ένα χρήσιμο εργαλείο για αυτόν τον σκοπό βρίσκεται στο [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), το οποίο διευκολύνει την εξαγωγή με την ένεση σε συνεδρίες και την εκφόρτωση των tickets στο `/tmp`.

Για να ρυθμίσετε και να χρησιμοποιήσετε αυτό το εργαλείο, ακολουθούνται τα παρακάτω βήματα:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Αυτή η διαδικασία θα προσπαθήσει να εισάγει σε διάφορες συνεδρίες, υποδεικνύοντας επιτυχία αποθηκεύοντας τα εξαγόμενα εισιτήρια στο `/tmp` με μια ονοματολογία `__krb_UID.ccache`.

### CCACHE ticket reuse από SSSD KCM

Το SSSD διατηρεί ένα αντίγραφο της βάσης δεδομένων στη διαδρομή `/var/lib/sss/secrets/secrets.ldb`. Το αντίστοιχο κλειδί αποθηκεύεται ως κρυφό αρχείο στη διαδρομή `/var/lib/sss/secrets/.secrets.mkey`. Από προεπιλογή, το κλειδί είναι αναγνώσιμο μόνο αν έχετε δικαιώματα **root**.

Η κλήση \*\*`SSSDKCMExtractor` \*\* με τις παραμέτρους --database και --key θα αναλύσει τη βάση δεδομένων και θα **αποκρυπτογραφήσει τα μυστικά**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Το **credential cache Kerberos blob μπορεί να μετατραπεί σε ένα χρησιμοποιήσιμο αρχείο Kerberos CCache** που μπορεί να περαστεί σε Mimikatz/Rubeus.

### CCACHE ticket reuse από keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Εξαγωγή λογαριασμών από το /etc/krb5.keytab

Τα κλειδιά λογαριασμού υπηρεσίας, που είναι απαραίτητα για υπηρεσίες που λειτουργούν με δικαιώματα root, αποθηκεύονται με ασφάλεια στα αρχεία **`/etc/krb5.keytab`**. Αυτά τα κλειδιά, παρόμοια με τους κωδικούς πρόσβασης για υπηρεσίες, απαιτούν αυστηρή εμπιστευτικότητα.

Για να ελέγξετε το περιεχόμενο του αρχείου keytab, μπορεί να χρησιμοποιηθεί το **`klist`**. Το εργαλείο έχει σχεδιαστεί για να εμφανίζει λεπτομέρειες κλειδιών, συμπεριλαμβανομένου του **NT Hash** για την αυθεντικοποίηση χρηστών, ιδιαίτερα όταν ο τύπος κλειδιού αναγνωρίζεται ως 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Για τους χρήστες Linux, **`KeyTabExtract`** προσφέρει λειτουργικότητα για την εξαγωγή του RC4 HMAC hash, το οποίο μπορεί να χρησιμοποιηθεί για την επαναχρησιμοποίηση του NTLM hash.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Στο macOS, **`bifrost`** χρησιμεύει ως εργαλείο ανάλυσης αρχείων keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Χρησιμοποιώντας τις εξαγόμενες πληροφορίες λογαριασμού και κατακερματισμού, μπορούν να δημιουργηθούν συνδέσεις με διακομιστές χρησιμοποιώντας εργαλεία όπως το **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Αναφορές
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
