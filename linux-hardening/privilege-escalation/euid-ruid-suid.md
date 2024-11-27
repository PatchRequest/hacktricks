# euid, ruid, suid

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


### User Identification Variables

- **`ruid`**: Ο **πραγματικός αναγνωριστικός αριθμός χρήστη** δηλώνει τον χρήστη που ξεκίνησε τη διαδικασία.
- **`euid`**: Γνωστός ως ο **αποτελεσματικός αναγνωριστικός αριθμός χρήστη**, αντιπροσωπεύει την ταυτότητα χρήστη που χρησιμοποιείται από το σύστημα για να προσδιορίσει τα δικαιώματα της διαδικασίας. Γενικά, το `euid` αντικατοπτρίζει το `ruid`, εκτός από περιπτώσεις όπως η εκτέλεση ενός εκτελέσιμου αρχείου SetUID, όπου το `euid` αναλαμβάνει την ταυτότητα του ιδιοκτήτη του αρχείου, παρέχοντας έτσι συγκεκριμένα δικαιώματα λειτουργίας.
- **`suid`**: Αυτός ο **αποθηκευμένος αναγνωριστικός αριθμός χρήστη** είναι κρίσιμος όταν μια διαδικασία υψηλών δικαιωμάτων (συνήθως εκτελείται ως root) χρειάζεται προσωρινά να παραιτηθεί από τα δικαιώματά της για να εκτελέσει ορισμένες εργασίες, μόνο για να ανακτήσει αργότερα την αρχική της ανυψωμένη κατάσταση.

#### Important Note
Μια διαδικασία που δεν λειτουργεί υπό root μπορεί να τροποποιήσει το `euid` της μόνο για να ταιριάζει με το τρέχον `ruid`, `euid` ή `suid`.

### Understanding set*uid Functions

- **`setuid`**: Σε αντίθεση με τις αρχικές υποθέσεις, το `setuid` τροποποιεί κυρίως το `euid` παρά το `ruid`. Συγκεκριμένα, για τις προνομιούχες διαδικασίες, ευθυγραμμίζει το `ruid`, το `euid` και το `suid` με τον καθορισμένο χρήστη, συχνά το root, εδραιώνοντας αποτελεσματικά αυτούς τους αναγνωριστικούς αριθμούς λόγω του υπερκαλύπτοντος `suid`. Λεπτομερείς πληροφορίες μπορούν να βρεθούν στη [σελίδα man του setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** και **`setresuid`**: Αυτές οι λειτουργίες επιτρέπουν την προσεκτική προσαρμογή του `ruid`, `euid` και `suid`. Ωστόσο, οι δυνατότητές τους εξαρτώνται από το επίπεδο προνομίων της διαδικασίας. Για διαδικασίες που δεν είναι root, οι τροποποιήσεις περιορίζονται στις τρέχουσες τιμές του `ruid`, `euid` και `suid`. Αντίθετα, οι διαδικασίες root ή αυτές με την ικανότητα `CAP_SETUID` μπορούν να αναθέσουν αυθαίρετες τιμές σε αυτούς τους αναγνωριστικούς αριθμούς. Περισσότερες πληροφορίες μπορούν να αντληθούν από τη [σελίδα man του setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) και τη [σελίδα man του setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Αυτές οι λειτουργίες σχεδιάστηκαν όχι ως μηχανισμός ασφαλείας αλλά για να διευκολύνουν τη σχεδιασμένη λειτουργική ροή, όπως όταν ένα πρόγραμμα υιοθετεί την ταυτότητα ενός άλλου χρήστη αλλάζοντας τον αποτελεσματικό αναγνωριστικό αριθμό χρήστη.

Είναι σημαντικό να σημειωθεί ότι ενώ το `setuid` μπορεί να είναι μια κοινή επιλογή για την ανύψωση προνομίων σε root (καθώς ευθυγραμμίζει όλους τους αναγνωριστικούς αριθμούς με το root), η διαφοροποίηση μεταξύ αυτών των λειτουργιών είναι κρίσιμη για την κατανόηση και την χειραγώγηση των συμπεριφορών αναγνωριστικών χρηστών σε διάφορα σενάρια.

### Program Execution Mechanisms in Linux

#### **`execve` System Call**
- **Functionality**: Το `execve` ξεκινά ένα πρόγραμμα, καθορισμένο από το πρώτο επιχείρημα. Δέχεται δύο πίνακες επιχειρημάτων, `argv` για τα επιχειρήματα και `envp` για το περιβάλλον.
- **Behavior**: Διατηρεί τον χώρο μνήμης του καλούντος αλλά ανανεώνει τη στοίβα, το σωρό και τα τμήματα δεδομένων. Ο κώδικας του προγράμματος αντικαθίσταται από το νέο πρόγραμμα.
- **User ID Preservation**:
- `ruid`, `euid` και πρόσθετοι αναγνωριστικοί αριθμοί ομάδας παραμένουν αμετάβλητοι.
- Το `euid` μπορεί να έχει λεπτές αλλαγές αν το νέο πρόγραμμα έχει οριστεί το SetUID bit.
- Το `suid` ενημερώνεται από το `euid` μετά την εκτέλεση.
- **Documentation**: Λεπτομερείς πληροφορίες μπορούν να βρεθούν στη [σελίδα man του `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **`system` Function**
- **Functionality**: Σε αντίθεση με το `execve`, το `system` δημιουργεί μια παιδική διαδικασία χρησιμοποιώντας το `fork` και εκτελεί μια εντολή μέσα σε αυτή την παιδική διαδικασία χρησιμοποιώντας το `execl`.
- **Command Execution**: Εκτελεί την εντολή μέσω του `sh` με `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Behavior**: Καθώς το `execl` είναι μια μορφή του `execve`, λειτουργεί παρόμοια αλλά στο πλαίσιο μιας νέας παιδικής διαδικασίας.
- **Documentation**: Περισσότερες πληροφορίες μπορούν να αποκτηθούν από τη [σελίδα man του `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Behavior of `bash` and `sh` with SUID**
- **`bash`**:
- Έχει μια επιλογή `-p` που επηρεάζει το πώς αντιμετωπίζονται το `euid` και το `ruid`.
- Χωρίς το `-p`, το `bash` ορίζει το `euid` στο `ruid` αν διαφέρουν αρχικά.
- Με το `-p`, διατηρείται το αρχικό `euid`.
- Περισσότερες λεπτομέρειες μπορούν να βρεθούν στη [σελίδα man του `bash`](https://linux.die.net/man/1/bash).
- **`sh`**:
- Δεν διαθέτει μηχανισμό παρόμοιο με το `-p` στο `bash`.
- Η συμπεριφορά σχετικά με τους αναγνωριστικούς αριθμούς χρηστών δεν αναφέρεται ρητά, εκτός από την επιλογή `-i`, που τονίζει τη διατήρηση της ισότητας του `euid` και του `ruid`.
- Πρόσθετες πληροφορίες είναι διαθέσιμες στη [σελίδα man του `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Αυτοί οι μηχανισμοί, διακριτοί στη λειτουργία τους, προσφέρουν μια ευέλικτη γκάμα επιλογών για την εκτέλεση και τη μετάβαση μεταξύ προγραμμάτων, με συγκεκριμένες λεπτομέρειες σχετικά με το πώς διαχειρίζονται και διατηρούνται οι αναγνωριστικοί αριθμοί χρηστών.

### Testing User ID Behaviors in Executions

Examples taken from https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, check it for further information

#### Case 1: Using `setuid` with `system`

**Objective**: Κατανόηση της επίδρασης του `setuid` σε συνδυασμό με το `system` και το `bash` ως `sh`.

**C Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Συγκέντρωση και Άδειες:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ανάλυση:**

* `ruid` και `euid` ξεκινούν ως 99 (κανένας) και 1000 (frank) αντίστοιχα.
* `setuid` ευθυγραμμίζει και τους δύο στο 1000.
* `system` εκτελεί `/bin/bash -c id` λόγω του symlink από sh σε bash.
* `bash`, χωρίς `-p`, προσαρμόζει το `euid` ώστε να ταιριάζει με το `ruid`, με αποτέλεσμα και οι δύο να είναι 99 (κανένας).

#### Περίπτωση 2: Χρησιμοποιώντας setreuid με system

**C Κώδικας**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Συγκέντρωση και Άδειες:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Εκτέλεση και Αποτέλεσμα:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ανάλυση:**

* `setreuid` ορίζει τόσο το ruid όσο και το euid σε 1000.
* `system` καλεί το bash, το οποίο διατηρεί τα αναγνωριστικά χρηστών λόγω της ισότητας τους, λειτουργώντας αποτελεσματικά ως frank.

#### Περίπτωση 3: Χρήση setuid με execve
Στόχος: Εξερεύνηση της αλληλεπίδρασης μεταξύ setuid και execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Εκτέλεση και Αποτέλεσμα:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ανάλυση:**

* `ruid` παραμένει 99, αλλά το euid έχει οριστεί σε 1000, σύμφωνα με την επίδραση του setuid.

**C Code Example 2 (Calling Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Εκτέλεση και Αποτέλεσμα:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ανάλυση:**

* Αν και το `euid` έχει οριστεί σε 1000 από το `setuid`, το `bash` επαναφέρει το euid σε `ruid` (99) λόγω της απουσίας του `-p`.

**C Code Example 3 (Using bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Εκτέλεση και Αποτέλεσμα:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Αναφορές
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Εμβαθύνετε την εμπειρία σας στην **Ασφάλεια Κινητών** με την 8kSec Academy. Εξασκηθείτε στην ασφάλεια iOS και Android μέσω των αυτορυθμιζόμενων μαθημάτων μας και αποκτήστε πιστοποίηση:

{% embed url="https://academy.8ksec.io/" %}


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
