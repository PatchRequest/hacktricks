# UTS Namespace

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Basic Information

Ένα UTS (UNIX Time-Sharing System) namespace είναι μια δυνατότητα του πυρήνα Linux που παρέχει **απομόνωση δύο αναγνωριστικών συστήματος**: το **hostname** και το **NIS** (Network Information Service) domain name. Αυτή η απομόνωση επιτρέπει σε κάθε UTS namespace να έχει το **δικό του ανεξάρτητο hostname και NIS domain name**, το οποίο είναι ιδιαίτερα χρήσιμο σε σενάρια κοντενέρωσης όπου κάθε κοντέινερ θα πρέπει να εμφανίζεται ως ξεχωριστό σύστημα με το δικό του hostname.

### How it works:

1. Όταν δημιουργείται ένα νέο UTS namespace, ξεκινά με μια **αντίγραφο του hostname και του NIS domain name από το γονικό namespace**. Αυτό σημαίνει ότι, κατά τη δημιουργία, το νέο namespace **μοιράζεται τα ίδια αναγνωριστικά με το γονικό του**. Ωστόσο, οποιεσδήποτε επακόλουθες αλλαγές στο hostname ή το NIS domain name εντός του namespace δεν θα επηρεάσουν άλλα namespaces.
2. Οι διαδικασίες εντός ενός UTS namespace **μπορούν να αλλάξουν το hostname και το NIS domain name** χρησιμοποιώντας τις κλήσεις συστήματος `sethostname()` και `setdomainname()`, αντίστοιχα. Αυτές οι αλλαγές είναι τοπικές στο namespace και δεν επηρεάζουν άλλα namespaces ή το σύστημα φιλοξενίας.
3. Οι διαδικασίες μπορούν να μετακινηθούν μεταξύ namespaces χρησιμοποιώντας την κλήση συστήματος `setns()` ή να δημιουργήσουν νέα namespaces χρησιμοποιώντας τις κλήσεις συστήματος `unshare()` ή `clone()` με την σημαία `CLONE_NEWUTS`. Όταν μια διαδικασία μετακινείται σε ένα νέο namespace ή δημιουργεί ένα, θα αρχίσει να χρησιμοποιεί το hostname και το NIS domain name που σχετίζονται με αυτό το namespace.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Με την τοποθέτηση μιας νέας παρουσίας του συστήματος αρχείων `/proc` αν χρησιμοποιήσετε την παράμετρο `--mount-proc`, διασφαλίζετε ότι η νέα mount namespace έχει μια **ακριβή και απομονωμένη άποψη των πληροφοριών διαδικασίας που είναι συγκεκριμένες για αυτή τη namespace**.

<details>

<summary>Σφάλμα: bash: fork: Cannot allocate memory</summary>

Όταν εκτελείται το `unshare` χωρίς την επιλογή `-f`, προκύπτει ένα σφάλμα λόγω του τρόπου που το Linux χειρίζεται τις νέες PID (Process ID) namespaces. Οι βασικές λεπτομέρειες και η λύση περιγράφονται παρακάτω:

1. **Εξήγηση Προβλήματος**:
- Ο πυρήνας του Linux επιτρέπει σε μια διαδικασία να δημιουργήσει νέες namespaces χρησιμοποιώντας την κλήση συστήματος `unshare`. Ωστόσο, η διαδικασία που ξεκινά τη δημιουργία μιας νέας PID namespace (αναφερόμενη ως η διαδικασία "unshare") δεν εισέρχεται στη νέα namespace; μόνο οι παιδικές της διαδικασίες το κάνουν.
- Η εκτέλεση `%unshare -p /bin/bash%` ξεκινά το `/bin/bash` στην ίδια διαδικασία με το `unshare`. Ως εκ τούτου, το `/bin/bash` και οι παιδικές του διαδικασίες βρίσκονται στην αρχική PID namespace.
- Η πρώτη παιδική διαδικασία του `/bin/bash` στη νέα namespace γίνεται PID 1. Όταν αυτή η διαδικασία τερματίσει, ενεργοποιεί την καθαριότητα της namespace αν δεν υπάρχουν άλλες διαδικασίες, καθώς το PID 1 έχει τον ειδικό ρόλο της υιοθέτησης ορφανών διαδικασιών. Ο πυρήνας του Linux θα απενεργοποιήσει στη συνέχεια την κατανομή PID σε αυτή τη namespace.

2. **Συνέπεια**:
- Η έξοδος του PID 1 σε μια νέα namespace οδηγεί στον καθαρισμό της σημαίας `PIDNS_HASH_ADDING`. Αυτό έχει ως αποτέλεσμα τη αποτυχία της συνάρτησης `alloc_pid` να κατανοήσει ένα νέο PID κατά τη δημιουργία μιας νέας διαδικασίας, παράγοντας το σφάλμα "Cannot allocate memory".

3. **Λύση**:
- Το πρόβλημα μπορεί να επιλυθεί χρησιμοποιώντας την επιλογή `-f` με το `unshare`. Αυτή η επιλογή κάνει το `unshare` να δημιουργήσει μια νέα διαδικασία μετά τη δημιουργία της νέας PID namespace.
- Η εκτέλεση `%unshare -fp /bin/bash%` διασφαλίζει ότι η εντολή `unshare` γίνεται PID 1 στη νέα namespace. Το `/bin/bash` και οι παιδικές του διαδικασίες είναι στη συνέχεια ασφαλώς περιορισμένες μέσα σε αυτή τη νέα namespace, αποτρέποντας την πρόωρη έξοδο του PID 1 και επιτρέποντας την κανονική κατανομή PID.

Διασφαλίζοντας ότι το `unshare` εκτελείται με την επιλογή `-f`, η νέα PID namespace διατηρείται σωστά, επιτρέποντας στο `/bin/bash` και τις υπο-διαδικασίες του να λειτουργούν χωρίς να συναντούν το σφάλμα κατανομής μνήμης.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Ελέγξτε σε ποιο namespace βρίσκεται η διαδικασία σας
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Βρείτε όλα τα UTS namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Είσοδος σε ένα UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
