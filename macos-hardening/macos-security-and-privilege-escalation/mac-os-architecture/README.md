# macOS Kernel & System Extensions

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## XNU Kernel

Ο **πυρήνας του macOS είναι ο XNU**, που σημαίνει "X is Not Unix". Αυτός ο πυρήνας αποτελείται θεμελιωδώς από τον **Mach microkernel** (θα συζητηθεί αργότερα), **και** στοιχεία από την Berkeley Software Distribution (**BSD**). Ο XNU παρέχει επίσης μια πλατφόρμα για **drivers πυρήνα μέσω ενός συστήματος που ονομάζεται I/O Kit**. Ο πυρήνας XNU είναι μέρος του ανοιχτού κώδικα έργου Darwin, που σημαίνει ότι **ο πηγαίος κώδικας του είναι ελεύθερα προσβάσιμος**.

Από την προοπτική ενός ερευνητή ασφαλείας ή ενός προγραμματιστή Unix, το **macOS** μπορεί να φαίνεται αρκετά **παρόμοιο** με ένα σύστημα **FreeBSD** με μια κομψή GUI και μια σειρά από προσαρμοσμένες εφαρμογές. Οι περισσότερες εφαρμογές που αναπτύσσονται για BSD θα μεταγλωττιστούν και θα εκτελούνται στο macOS χωρίς να χρειάζονται τροποποιήσεις, καθώς τα εργαλεία γραμμής εντολών που είναι οικεία στους χρήστες Unix είναι όλα παρόντα στο macOS. Ωστόσο, επειδή ο πυρήνας XNU ενσωματώνει τον Mach, υπάρχουν κάποιες σημαντικές διαφορές μεταξύ ενός παραδοσιακού συστήματος τύπου Unix και του macOS, και αυτές οι διαφορές μπορεί να προκαλέσουν πιθανά προβλήματα ή να προσφέρουν μοναδικά πλεονεκτήματα.

Ανοιχτός κώδικας έκδοση του XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Ο Mach είναι ένας **microkernel** σχεδιασμένος να είναι **συμβατός με UNIX**. ΈPrinciple του σχεδιασμού του ήταν να **ελαχιστοποιήσει** την ποσότητα του **κώδικα** που εκτελείται στον **χώρο πυρήνα** και αντ' αυτού να επιτρέπει πολλές τυπικές λειτουργίες του πυρήνα, όπως το σύστημα αρχείων, το δίκτυο και το I/O, να **εκτελούνται ως εργασίες επιπέδου χρήστη**.

Στον XNU, ο Mach είναι **υπεύθυνος για πολλές από τις κρίσιμες χαμηλού επιπέδου λειτουργίες** που συνήθως χειρίζεται ένας πυρήνας, όπως ο προγραμματισμός επεξεργαστή, η πολυδιεργασία και η διαχείριση εικονικής μνήμης.

### BSD

Ο πυρήνας XNU **ενσωματώνει** επίσης μια σημαντική ποσότητα κώδικα που προέρχεται από το έργο **FreeBSD**. Αυτός ο κώδικας **εκτελείται ως μέρος του πυρήνα μαζί με τον Mach**, στον ίδιο χώρο διευθύνσεων. Ωστόσο, ο κώδικας FreeBSD μέσα στον XNU μπορεί να διαφέρει σημαντικά από τον αρχικό κώδικα FreeBSD επειδή απαιτούνταν τροποποιήσεις για να διασφαλιστεί η συμβατότητά του με τον Mach. Το FreeBSD συμβάλλει σε πολλές λειτουργίες του πυρήνα, συμπεριλαμβανομένων:

* Διαχείριση διεργασιών
* Διαχείριση σημάτων
* Βασικοί μηχανισμοί ασφαλείας, συμπεριλαμβανομένης της διαχείρισης χρηστών και ομάδων
* Υποδομή κλήσεων συστήματος
* Στοίβα TCP/IP και sockets
* Firewall και φιλτράρισμα πακέτων

Η κατανόηση της αλληλεπίδρασης μεταξύ BSD και Mach μπορεί να είναι περίπλοκη, λόγω των διαφορετικών εννοιολογικών πλαισίων τους. Για παράδειγμα, το BSD χρησιμοποιεί διεργασίες ως τη θεμελιώδη μονάδα εκτέλεσης του, ενώ ο Mach λειτουργεί με βάση τα νήματα. Αυτή η διαφορά συμφιλιώνεται στον XNU με την **συσχέτιση κάθε διεργασίας BSD με μια εργασία Mach** που περιέχει ακριβώς ένα νήμα Mach. Όταν χρησιμοποιείται η κλήση συστήματος fork() του BSD, ο κώδικας BSD μέσα στον πυρήνα χρησιμοποιεί τις λειτουργίες Mach για να δημιουργήσει μια εργασία και μια δομή νήματος.

Επιπλέον, **ο Mach και το BSD διατηρούν διαφορετικά μοντέλα ασφαλείας**: το μοντέλο ασφαλείας του **Mach** βασίζεται στα **δικαιώματα θυρών**, ενώ το μοντέλο ασφαλείας του BSD λειτουργεί με βάση την **ιδιοκτησία διεργασιών**. Οι διαφορές μεταξύ αυτών των δύο μοντέλων έχουν κατά καιρούς οδηγήσει σε τοπικές ευπάθειες ανύψωσης προνομίων. Εκτός από τις τυπικές κλήσεις συστήματος, υπάρχουν επίσης **παγίδες Mach που επιτρέπουν στα προγράμματα χώρου χρήστη να αλληλεπιδρούν με τον πυρήνα**. Αυτά τα διαφορετικά στοιχεία μαζί σχηματίζουν την πολύπλευρη, υβριδική αρχιτεκτονική του πυρήνα macOS.

### I/O Kit - Drivers

Το I/O Kit είναι ένα ανοιχτού κώδικα, αντικειμενοστραφές **πλαίσιο οδηγών συσκευών** στον πυρήνα XNU, που χειρίζεται **δυναμικά φορτωμένους οδηγούς συσκευών**. Επιτρέπει την προσθήκη αρθρωτού κώδικα στον πυρήνα εν κινήσει, υποστηρίζοντας ποικιλία υλικού.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Inter Process Communication

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

## macOS Kernel Extensions

Το macOS είναι **πολύ περιοριστικό για τη φόρτωση επεκτάσεων πυρήνα** (.kext) λόγω των υψηλών προνομίων με τα οποία θα εκτελείται ο κώδικας. Στην πραγματικότητα, από προεπιλογή είναι σχεδόν αδύνατο (εκτός αν βρεθεί μια παράκαμψη).

Στην επόμενη σελίδα μπορείτε επίσης να δείτε πώς να ανακτήσετε το `.kext` που φορτώνει το macOS μέσα στο **kernelcache**:

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS System Extensions

Αντί να χρησιμοποιεί επεκτάσεις πυρήνα, το macOS δημιούργησε τις επεκτάσεις συστήματος, οι οποίες προσφέρουν APIs επιπέδου χρήστη για αλληλεπίδραση με τον πυρήνα. Με αυτόν τον τρόπο, οι προγραμματιστές μπορούν να αποφύγουν τη χρήση επεκτάσεων πυρήνα.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## References

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
