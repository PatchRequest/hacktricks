# macOS Keychain

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Main Keychains

* The **User Keychain** (`~/Library/Keychains/login.keychain-db`), which is used to store **credentials που σχετίζονται με τον χρήστη** όπως κωδικούς πρόσβασης εφαρμογών, κωδικούς πρόσβασης στο διαδίκτυο, πιστοποιητικά που δημιουργούνται από τον χρήστη, κωδικούς πρόσβασης δικτύου και δημόσιους/ιδιωτικούς κωδικούς που δημιουργούνται από τον χρήστη.
* The **System Keychain** (`/Library/Keychains/System.keychain`), which stores **credentials σε επίπεδο συστήματος** όπως κωδικούς πρόσβασης WiFi, πιστοποιητικά ρίζας συστήματος, ιδιωτικούς κωδικούς συστήματος και κωδικούς πρόσβασης εφαρμογών συστήματος.
* It's possible to find other components like certificates in `/System/Library/Keychains/*`
* In **iOS** there is only one **Keychain** located in `/private/var/Keychains/`. This folder also contains databases for the `TrustStore`, certificates authorities (`caissuercache`) and OSCP entries (`ocspache`).
* Apps will be restricted in the keychain only to their private area based on their application identifier.

### Password Keychain Access

These files, while they do not have inherent protection and can be **downloaded**, are encrypted and require the **plaintext κωδικό πρόσβασης του χρήστη για να αποκρυπτογραφηθούν**. A tool like [**Chainbreaker**](https://github.com/n0fate/chainbreaker) could be used for decryption.

## Keychain Entries Protections

### ACLs

Each entry in the keychain is governed by **Access Control Lists (ACLs)** which dictate who can perform various actions on the keychain entry, including:

* **ACLAuhtorizationExportClear**: Allows the holder to get the clear text of the secret.
* **ACLAuhtorizationExportWrapped**: Allows the holder to get the clear text encrypted with another provided password.
* **ACLAuhtorizationAny**: Allows the holder to perform any action.

The ACLs are further accompanied by a **list of trusted applications** that can perform these actions without prompting. This could be:

* **N`il`** (no authorization required, **everyone is trusted**)
* An **empty** list (**nobody** is trusted)
* **List** of specific **applications**.

Also the entry might contain the key **`ACLAuthorizationPartitionID`,** which is use to identify the **teamid, apple,** and **cdhash.**

* If the **teamid** is specified, then in order to **access the entry** value **withuot** a **prompt** the used application must have the **same teamid**.
* If the **apple** is specified, then the app needs to be **signed** by **Apple**.
* If the **cdhash** is indicated, then **app** must have the specific **cdhash**.

### Creating a Keychain Entry

When a **new** **entry** is created using **`Keychain Access.app`**, the following rules apply:

* All apps can encrypt.
* **No apps** can export/decrypt (without prompting the user).
* All apps can see the integrity check.
* No apps can change ACLs.
* The **partitionID** is set to **`apple`**.

When an **application creates an entry in the keychain**, the rules are slightly different:

* All apps can encrypt.
* Only the **creating application** (or any other apps explicitly added) can export/decrypt (without prompting the user).
* All apps can see the integrity check.
* No apps can change the ACLs.
* The **partitionID** is set to **`teamid:[teamID here]`**.

## Accessing the Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
Η **καταμέτρηση και εξαγωγή** μυστικών από το **keychain** που **δεν θα δημιουργήσει προτροπή** μπορεί να γίνει με το εργαλείο [**LockSmith**](https://github.com/its-a-feature/LockSmith)

Άλλες τελικές API μπορούν να βρεθούν στον κώδικα πηγής [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity\_keychain/libsecurity\_keychain-55017/lib/SecKeychain.h.auto.html).
{% endhint %}

Λίστα και λήψη **πληροφοριών** για κάθε καταχώρηση keychain χρησιμοποιώντας το **Security Framework** ή μπορείτε επίσης να ελέγξετε το εργαλείο cli ανοιχτού κώδικα της Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Ορισμένα παραδείγματα API:

* Η API **`SecItemCopyMatching`** δίνει πληροφορίες για κάθε καταχώρηση και υπάρχουν ορισμένα χαρακτηριστικά που μπορείτε να ορίσετε κατά τη χρήση της:
* **`kSecReturnData`**: Αν είναι αληθές, θα προσπαθήσει να αποκρυπτογραφήσει τα δεδομένα (ορίστε σε ψευδές για να αποφύγετε πιθανές αναδυόμενες ειδοποιήσεις)
* **`kSecReturnRef`**: Λάβετε επίσης αναφορά στο στοιχείο keychain (ορίστε σε αληθές σε περίπτωση που αργότερα δείτε ότι μπορείτε να αποκρυπτογραφήσετε χωρίς αναδυόμενη ειδοποίηση)
* **`kSecReturnAttributes`**: Λάβετε μεταδεδομένα σχετικά με τις καταχωρήσεις
* **`kSecMatchLimit`**: Πόσα αποτελέσματα να επιστραφούν
* **`kSecClass`**: Τι είδους καταχώρηση keychain

Λάβετε **ACLs** κάθε καταχώρησης:

* Με την API **`SecAccessCopyACLList`** μπορείτε να λάβετε το **ACL για το στοιχείο keychain**, και θα επιστρέψει μια λίστα ACL (όπως `ACLAuhtorizationExportClear` και οι άλλες που αναφέρθηκαν προηγουμένως) όπου κάθε λίστα έχει:
* Περιγραφή
* **Λίστα Εμπιστευμένων Εφαρμογών**. Αυτό θα μπορούσε να είναι:
* Μια εφαρμογή: /Applications/Slack.app
* Ένα δυαδικό: /usr/libexec/airportd
* Μια ομάδα: group://AirPort

Εξαγωγή των δεδομένων:

* Η API **`SecKeychainItemCopyContent`** αποκτά το απλό κείμενο
* Η API **`SecItemExport`** εξάγει τα κλειδιά και τα πιστοποιητικά αλλά μπορεί να χρειαστεί να ορίσετε κωδικούς πρόσβασης για να εξάγετε το περιεχόμενο κρυπτογραφημένο

Και αυτές είναι οι **απαιτήσεις** για να μπορείτε να **εξάγετε ένα μυστικό χωρίς προτροπή**:

* Αν **1+ εμπιστευμένες** εφαρμογές αναφέρονται:
* Χρειάζεστε τις κατάλληλες **εξουσιοδοτήσεις** (**`Nil`**, ή να είστε **μέρος** της επιτρεπόμενης λίστας εφαρμογών στην εξουσιοδότηση για πρόσβαση στις μυστικές πληροφορίες)
* Χρειάζεστε υπογραφή κώδικα που να ταιριάζει με το **PartitionID**
* Χρειάζεστε υπογραφή κώδικα που να ταιριάζει με αυτήν μιας **εμπιστευμένης εφαρμογής** (ή να είστε μέλος της σωστής ομάδας πρόσβασης Keychain)
* Αν **όλες οι εφαρμογές είναι εμπιστευμένες**:
* Χρειάζεστε τις κατάλληλες **εξουσιοδοτήσεις**
* Χρειάζεστε υπογραφή κώδικα που να ταιριάζει με το **PartitionID**
* Αν **δεν υπάρχει PartitionID**, τότε αυτό δεν είναι απαραίτητο

{% hint style="danger" %}
Επομένως, αν υπάρχει **1 εφαρμογή αναφερόμενη**, χρειάζεστε να **εισάγετε κώδικα σε αυτήν την εφαρμογή**.

Αν **apple** αναφέρεται στο **partitionID**, μπορείτε να έχετε πρόσβαση σε αυτό με **`osascript`** οπότε οτιδήποτε εμπιστεύεται όλες τις εφαρμογές με apple στο partitionID. **`Python`** θα μπορούσε επίσης να χρησιμοποιηθεί για αυτό.
{% endhint %}

### Δύο επιπλέον χαρακτηριστικά

* **Αόρατο**: Είναι μια λογική σημαία για να **κρύψει** την καταχώρηση από την εφαρμογή **UI** Keychain
* **Γενικό**: Είναι για την αποθήκευση **μεταδεδομένων** (οπότε ΔΕΝ είναι ΚΡΥΠΤΟΓΡΑΦΗΜΕΝΟ)
* Η Microsoft αποθήκευε σε απλό κείμενο όλους τους ανανεωτικούς κωδικούς πρόσβασης για πρόσβαση σε ευαίσθητους τελικούς προορισμούς.

## Αναφορές

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
