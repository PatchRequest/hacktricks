# macOS Security & Privilege Escalation

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Εγγραφείτε στον [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server για να επικοινωνήσετε με έμπειρους hackers και hunters bug bounty!

**Ενημερώσεις Hacking**\
Ασχοληθείτε με περιεχόμενο που εμβαθύνει στην αδρεναλίνη και τις προκλήσεις του hacking

**Ειδήσεις Hack σε Πραγματικό Χρόνο**\
Μείνετε ενημερωμένοι με τον ταχύτατο κόσμο του hacking μέσω ειδήσεων και πληροφοριών σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενημερωμένοι με τις πιο πρόσφατες bug bounties που ξεκινούν και κρίσιμες ενημερώσεις πλατφόρμας

**Εγγραφείτε μαζί μας στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και ξεκινήστε να συνεργάζεστε με κορυφαίους hackers σήμερα!

## Βασικά MacOS

Αν δεν είστε εξοικειωμένοι με το macOS, θα πρέπει να ξεκινήσετε να μαθαίνετε τα βασικά του macOS:

* Ειδικά αρχεία & δικαιώματα **macOS:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Κοινές **χρήστες macOS**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* Η **αρχιτεκτονική** του k**ernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Κοινές υπηρεσίες & πρωτόκολλα δικτύου **macOS**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Ανοιχτού κώδικα** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Για να κατεβάσετε ένα `tar.gz` αλλάξτε μια διεύθυνση URL όπως [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) σε [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Σε εταιρείες, τα συστήματα **macOS** είναι πολύ πιθανό να είναι **διαχειριζόμενα με MDM**. Επομένως, από την προοπτική ενός επιτιθέμενου είναι ενδιαφέρον να γνωρίζει **πώς λειτουργεί αυτό**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Επιθεώρηση, Αποσφαλμάτωση και Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Προστασίες Ασφαλείας MacOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Επιφάνεια Επίθεσης

### Δικαιώματα Αρχείων

Αν μια **διαδικασία που εκτελείται ως root γράφει** ένα αρχείο που μπορεί να ελεγχθεί από έναν χρήστη, ο χρήστης θα μπορούσε να το εκμεταλλευτεί για να **κάνει κλιμάκωση δικαιωμάτων**.\
Αυτό θα μπορούσε να συμβεί στις παρακάτω καταστάσεις:

* Το αρχείο που χρησιμοποιήθηκε είχε ήδη δημιουργηθεί από έναν χρήστη (ανήκει στον χρήστη)
* Το αρχείο που χρησιμοποιήθηκε είναι εγγράψιμο από τον χρήστη λόγω ομάδας
* Το αρχείο που χρησιμοποιήθηκε είναι μέσα σε έναν φάκελο που ανήκει στον χρήστη (ο χρήστης θα μπορούσε να δημιουργήσει το αρχείο)
* Το αρχείο που χρησιμοποιήθηκε είναι μέσα σε έναν φάκελο που ανήκει στον root αλλά ο χρήστης έχει δικαίωμα εγγραφής σε αυτόν λόγω ομάδας (ο χρήστης θα μπορούσε να δημιουργήσει το αρχείο)

Η δυνατότητα **δημιουργίας ενός αρχείου** που θα χρησιμοποιηθεί από τον **root**, επιτρέπει σε έναν χρήστη να **εκμεταλλευτεί το περιεχόμενό του** ή ακόμα και να δημιουργήσει **symlinks/hardlinks** για να το δείξει σε άλλη τοποθεσία.

Για αυτού του είδους τις ευπάθειες μην ξεχάσετε να **ελέγξετε ευάλωτους εγκαταστάτες `.pkg`**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Χειριστές Εφαρμογών Επέκτασης Αρχείων & Σχεδίου URL

Περίεργες εφαρμογές που έχουν καταχωρηθεί από επεκτάσεις αρχείων θα μπορούσαν να εκμεταλλευτούν και διαφορετικές εφαρμογές μπορούν να καταχωρηθούν για να ανοίξουν συγκεκριμένα πρωτόκολλα

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Κλιμάκωση Δικαιωμάτων

Στο macOS, οι **εφαρμογές και τα αρχεία εκτελέσιμα μπορούν να έχουν δικαιώματα** για πρόσβαση σε φακέλους ή ρυθμίσεις που τους καθιστούν πιο προνομιούχες από άλλες.

Επομένως, ένας επιτιθέμενος που θέλει να συμβιβάσει επιτυχώς μια μηχανή macOS θα χρειαστεί να **κλιμακώσει τα δικαιώματα TCC** του (ή ακόμα και **να παρακάμψει το SIP**, ανάλογα με τις ανάγκες του).

Αυτά τα δικαιώματα δίνονται συνήθως με τη μορφή **entitlements** με τα οποία είναι υπογεγραμμένη η εφαρμογή, ή η εφαρμογή μπορεί να ζητήσει κάποιες προσβάσεις και μετά την **έγκριση τους από τον χρήστη** μπορούν να βρεθούν στις **βάσεις δεδομένων TCC**. Ένας άλλος τρόπος με τον οποίο μια διαδικασία μπορεί να αποκτήσει αυτά τα δικαιώματα είναι να είναι **παιδί μιας διαδικασίας** με αυτά τα **δικαιώματα** καθώς συνήθως **κληρονομούνται**.

Ακολουθήστε αυτούς τους συνδέσμους για να βρείτε διαφορετικούς τρόπους για [**να κλιμακώσετε δικαιώματα στο TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), για [**να παρακάμψετε το TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) και πώς στο παρελθόν [**έχει παρακαμφθεί το SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Παραδοσιακή Κλιμάκωση Δικαιωμάτων

Φυσικά από την προοπτική των κόκκινων ομάδων θα πρέπει επίσης να ενδιαφέρεστε να κλιμακώσετε σε root. Ελέγξτε την παρακάτω ανάρτηση για μερικές συμβουλές:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## Συμμόρφωση macOS

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos_security)

## Αναφορές

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Εγγραφείτε στον [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server για να επικοινωνήσετε με έμπειρους hackers και hunters bug bounty!

**Ενημερώσεις Hacking**\
Ασχοληθείτε με περιεχόμενο που εμβαθύνει στην αδρεναλίνη και τις προκλήσεις του hacking

**Ειδήσεις Hack σε Πραγματικό Χρόνο**\
Μείνετε ενημερωμένοι με τον ταχύτατο κόσμο του hacking μέσω ειδήσεων και πληροφοριών σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενημερωμένοι με τις πιο πρόσφατες bug bounties που ξεκινούν και κρίσιμες ενημερώσεις πλατφόρμας

**Εγγραφείτε μαζί μας στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και ξεκινήστε να συνεργάζεστε με κορυφαίους hackers σήμερα!

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
