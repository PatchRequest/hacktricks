# macOS Kernel Extensions & Debugging

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

## Basic Information

Οι επεκτάσεις πυρήνα (Kexts) είναι **πακέτα** με κατάληξη **`.kext`** που **φορτώνονται απευθείας στον χώρο του πυρήνα macOS**, παρέχοντας επιπλέον λειτουργικότητα στο κύριο λειτουργικό σύστημα.

### Requirements

Προφανώς, αυτό είναι τόσο ισχυρό που είναι **περίπλοκο να φορτωθεί μια επέκταση πυρήνα**. Αυτές είναι οι **απαιτήσεις** που πρέπει να πληροί μια επέκταση πυρήνα για να φορτωθεί:

* Όταν **μπαίνετε σε λειτουργία ανάκτησης**, οι επεκτάσεις πυρήνα **πρέπει να επιτρέπεται** να φορτωθούν:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Η επέκταση πυρήνα πρέπει να είναι **υπογεγραμμένη με πιστοποιητικό υπογραφής κώδικα πυρήνα**, το οποίο μπορεί να **χορηγηθεί μόνο από την Apple**. Ποιος θα εξετάσει λεπτομερώς την εταιρεία και τους λόγους για τους οποίους είναι απαραίτητο.
* Η επέκταση πυρήνα πρέπει επίσης να είναι **notarized**, η Apple θα μπορεί να την ελέγξει για κακόβουλο λογισμικό.
* Στη συνέχεια, ο χρήστης **root** είναι αυτός που μπορεί να **φορτώσει την επέκταση πυρήνα** και τα αρχεία μέσα στο πακέτο πρέπει να **ανήκουν στον root**.
* Κατά τη διαδικασία φόρτωσης, το πακέτο πρέπει να είναι προετοιμασμένο σε μια **προστατευμένη τοποθεσία μη root**: `/Library/StagedExtensions` (απαιτεί την χορήγηση `com.apple.rootless.storage.KernelExtensionManagement`).
* Τέλος, όταν προσπαθεί να το φορτώσει, ο χρήστης θα [**λάβει ένα αίτημα επιβεβαίωσης**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) και, αν γίνει αποδεκτό, ο υπολογιστής πρέπει να **επανεκκινήσει** για να το φορτώσει.

### Loading process

Στο Catalina ήταν έτσι: Είναι ενδιαφέρον να σημειωθεί ότι η **διαδικασία επαλήθευσης** συμβαίνει σε **userland**. Ωστόσο, μόνο οι εφαρμογές με την **χορήγηση `com.apple.private.security.kext-management`** μπορούν να **ζητήσουν από τον πυρήνα να φορτώσει μια επέκταση**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **ξεκινά** τη **διαδικασία επαλήθευσης** για τη φόρτωση μιας επέκτασης
* Θα επικοινωνήσει με **`kextd`** στέλνοντας χρησιμοποιώντας μια **υπηρεσία Mach**.
2. **`kextd`** θα ελέγξει διάφορα πράγματα, όπως την **υπογραφή**
* Θα επικοινωνήσει με **`syspolicyd`** για να **ελέγξει** αν η επέκταση μπορεί να **φορτωθεί**.
3. **`syspolicyd`** θα **ζητήσει** από τον **χρήστη** αν η επέκταση δεν έχει φορτωθεί προηγουμένως.
* **`syspolicyd`** θα αναφέρει το αποτέλεσμα στον **`kextd`**
4. **`kextd`** θα είναι τελικά σε θέση να **πεί** στον πυρήνα να φορτώσει την επέκταση

Αν **`kextd`** δεν είναι διαθέσιμο, **`kextutil`** μπορεί να εκτελέσει τους ίδιους ελέγχους.

### Enumeration (loaded kexts)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

{% hint style="danger" %}
Αν και οι επεκτάσεις πυρήνα αναμένονται να βρίσκονται στο `/System/Library/Extensions/`, αν πάτε σε αυτόν τον φάκελο **δεν θα βρείτε κανένα δυαδικό αρχείο**. Αυτό οφείλεται στο **kernelcache** και για να αναστρέψετε ένα `.kext` πρέπει να βρείτε έναν τρόπο να το αποκτήσετε.
{% endhint %}

Το **kernelcache** είναι μια **προ-συγκεντρωμένη και προ-συνδεδεμένη έκδοση του πυρήνα XNU**, μαζί με βασικούς **οδηγούς** και **επεκτάσεις πυρήνα**. Αποθηκεύεται σε **συμπιεσμένη** μορφή και αποσυμπιέζεται στη μνήμη κατά τη διαδικασία εκκίνησης. Το kernelcache διευκολύνει έναν **ταχύτερο χρόνο εκκίνησης** έχοντας μια έτοιμη προς εκτέλεση έκδοση του πυρήνα και κρίσιμων οδηγών διαθέσιμων, μειώνοντας τον χρόνο και τους πόρους που θα δαπανώνταν διαφορετικά για τη δυναμική φόρτωση και σύνδεση αυτών των στοιχείων κατά την εκκίνηση.

### Τοπικό Kernelcache

Στο iOS βρίσκεται στο **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** στο macOS μπορείτε να το βρείτε με: **`find / -name "kernelcache" 2>/dev/null`** \
Στην περίπτωσή μου στο macOS το βρήκα στο:

* `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Η μορφή αρχείου IMG4 είναι μια μορφή κοντέινερ που χρησιμοποιείται από την Apple στα iOS και macOS συσκευές για την ασφαλή **αποθήκευση και επαλήθευση των στοιχείων υλικολογισμικού** (όπως το **kernelcache**). Η μορφή IMG4 περιλαμβάνει μια κεφαλίδα και αρκετές ετικέτες που περι encapsulate διάφορα κομμάτια δεδομένων, συμπεριλαμβανομένου του πραγματικού φορτίου (όπως ένας πυρήνας ή bootloader), μια υπογραφή και ένα σύνολο ιδιοτήτων manifest. Η μορφή υποστηρίζει κρυπτογραφική επαλήθευση, επιτρέποντας στη συσκευή να επιβεβαιώσει την αυθεντικότητα και την ακεραιότητα του στοιχείου υλικολογισμικού πριν το εκτελέσει.

Συνήθως αποτελείται από τα εξής στοιχεία:

* **Payload (IM4P)**:
* Συχνά συμπιεσμένο (LZFSE4, LZSS, …)
* Προαιρετικά κρυπτογραφημένο
* **Manifest (IM4M)**:
* Περιέχει Υπογραφή
* Πρόσθετο λεξικό Κλειδιού/Τιμής
* **Restore Info (IM4R)**:
* Γνωστό και ως APNonce
* Αποτρέπει την επανάληψη ορισμένων ενημερώσεων
* ΠΡΟΑΙΡΕΤΙΚΟ: Συνήθως αυτό δεν βρίσκεται

Αποσυμπιέστε το Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Download&#x20;

* [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Στο [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) είναι δυνατή η εύρεση όλων των πακέτων αποσφαλμάτωσης πυρήνα. Μπορείτε να το κατεβάσετε, να το τοποθετήσετε, να το ανοίξετε με το εργαλείο [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), να αποκτήσετε πρόσβαση στον φάκελο **`.kext`** και **να το εξαγάγετε**.

Ελέγξτε το για σύμβολα με:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
* [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Κάποιες φορές η Apple κυκλοφορεί **kernelcache** με **symbols**. Μπορείτε να κατεβάσετε κάποιες εκδόσεις λογισμικού με symbols ακολουθώντας τους συνδέσμους σε αυτές τις σελίδες. Οι εκδόσεις λογισμικού θα περιέχουν το **kernelcache** μεταξύ άλλων αρχείων.

Για να **extract** τα αρχεία, ξεκινήστε αλλάζοντας την επέκταση από `.ipsw` σε `.zip` και **unzip** το.

Αφού εξαγάγετε την έκδοση λογισμικού, θα λάβετε ένα αρχείο όπως: **`kernelcache.release.iphone14`**. Είναι σε μορφή **IMG4**, μπορείτε να εξαγάγετε τις ενδιαφέρουσες πληροφορίες με:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspecting kernelcache

Ελέγξτε αν το kernelcache έχει σύμβολα με
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Με αυτό μπορούμε τώρα **να εξάγουμε όλες τις επεκτάσεις** ή την **μία που σας ενδιαφέρει:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Debugging



## Αναφορές

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

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
