# macOS Code Signing

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

Τα Mach-o δυαδικά περιέχουν μια εντολή φόρτωσης που ονομάζεται **`LC_CODE_SIGNATURE`** που υποδεικνύει την **απόσταση** και το **μέγεθος** των υπογραφών μέσα στο δυαδικό. Στην πραγματικότητα, χρησιμοποιώντας το εργαλείο GUI MachOView, είναι δυνατόν να βρείτε στο τέλος του δυαδικού μια ενότητα που ονομάζεται **Code Signature** με αυτές τις πληροφορίες:

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Η μαγική κεφαλίδα της Code Signature είναι **`0xFADE0CC0`**. Στη συνέχεια, έχετε πληροφορίες όπως το μήκος και τον αριθμό των blobs του superBlob που τα περιέχει.\
Είναι δυνατόν να βρείτε αυτές τις πληροφορίες στον [πηγαίο κώδικα εδώ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276):
```c
/*
* Structure of an embedded-signature SuperBlob
*/

typedef struct __BlobIndex {
uint32_t type;                                  /* type of entry */
uint32_t offset;                                /* offset of entry */
} CS_BlobIndex
__attribute__ ((aligned(1)));

typedef struct __SC_SuperBlob {
uint32_t magic;                                 /* magic number */
uint32_t length;                                /* total length of SuperBlob */
uint32_t count;                                 /* number of index entries following */
CS_BlobIndex index[];                   /* (count) entries */
/* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob
__attribute__ ((aligned(1)));

#define KERNEL_HAVE_CS_GENERICBLOB 1
typedef struct __SC_GenericBlob {
uint32_t magic;                                 /* magic number */
uint32_t length;                                /* total length of blob */
char data[];
} CS_GenericBlob
__attribute__ ((aligned(1)));
```
Κοινά blobs που περιέχονται είναι ο Κατάλογος Κώδικα, οι Απαιτήσεις και τα Δικαιώματα και μια Κρυπτογραφική Σύνταξη Μηνύματος (CMS).\
Επιπλέον, σημειώστε πώς τα δεδομένα που κωδικοποιούνται στα blobs είναι κωδικοποιημένα σε **Big Endian.**

Επιπλέον, οι υπογραφές μπορούν να αποσπαστούν από τα δυαδικά αρχεία και να αποθηκευτούν στο `/var/db/DetachedSignatures` (χρησιμοποιείται από το iOS).

## Blob Καταλόγου Κώδικα

Είναι δυνατόν να βρείτε τη δήλωση του [Blob Καταλόγου Κώδικα στον κώδικα](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104):
```c
typedef struct __CodeDirectory {
uint32_t magic;                                 /* magic number (CSMAGIC_CODEDIRECTORY) */
uint32_t length;                                /* total length of CodeDirectory blob */
uint32_t version;                               /* compatibility version */
uint32_t flags;                                 /* setup and mode flags */
uint32_t hashOffset;                    /* offset of hash slot element at index zero */
uint32_t identOffset;                   /* offset of identifier string */
uint32_t nSpecialSlots;                 /* number of special hash slots */
uint32_t nCodeSlots;                    /* number of ordinary (code) hash slots */
uint32_t codeLimit;                             /* limit to main image signature range */
uint8_t hashSize;                               /* size of each hash in bytes */
uint8_t hashType;                               /* type of hash (cdHashType* constants) */
uint8_t platform;                               /* platform identifier; zero if not platform binary */
uint8_t pageSize;                               /* log2(page size in bytes); 0 => infinite */
uint32_t spare2;                                /* unused (must be zero) */

char end_earliest[0];

/* Version 0x20100 */
uint32_t scatterOffset;                 /* offset of optional scatter vector */
char end_withScatter[0];

/* Version 0x20200 */
uint32_t teamOffset;                    /* offset of optional team identifier */
char end_withTeam[0];

/* Version 0x20300 */
uint32_t spare3;                                /* unused (must be zero) */
uint64_t codeLimit64;                   /* limit to main image signature range, 64 bits */
char end_withCodeLimit64[0];

/* Version 0x20400 */
uint64_t execSegBase;                   /* offset of executable segment */
uint64_t execSegLimit;                  /* limit of executable segment */
uint64_t execSegFlags;                  /* executable segment flags */
char end_withExecSeg[0];

/* Version 0x20500 */
uint32_t runtime;
uint32_t preEncryptOffset;
char end_withPreEncryptOffset[0];

/* Version 0x20600 */
uint8_t linkageHashType;
uint8_t linkageApplicationType;
uint16_t linkageApplicationSubType;
uint32_t linkageOffset;
uint32_t linkageSize;
char end_withLinkage[0];

/* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory
__attribute__ ((aligned(1)));
```
Σημειώστε ότι υπάρχουν διαφορετικές εκδόσεις αυτής της δομής όπου οι παλιές μπορεί να περιέχουν λιγότερες πληροφορίες.

## Σελίδες Υπογραφής Κώδικα

Η κατακερματισμένη μορφή του πλήρους δυαδικού θα ήταν αναποτελεσματική και ακόμη και άχρηστη αν φορτωθεί μόνο μερικώς στη μνήμη. Επομένως, η υπογραφή κώδικα είναι στην πραγματικότητα ένας κατακερματισμός κατακερματισμών όπου κάθε δυαδική σελίδα κατακερματίζεται ατομικά.\
Στην πραγματικότητα, στον προηγούμενο κώδικα **Καταλόγου Κώδικα** μπορείτε να δείτε ότι το **μέγεθος της σελίδας καθορίζεται** σε ένα από τα πεδία του. Επιπλέον, αν το μέγεθος του δυαδικού δεν είναι πολλαπλάσιο του μεγέθους μιας σελίδας, το πεδίο **CodeLimit** καθορίζει πού είναι το τέλος της υπογραφής.
```bash
# Get all hashes of /bin/ps
codesign -d -vvvvvv /bin/ps
[...]
CandidateCDHash sha256=c46e56e9490d93fe35a76199bdb367b3463c91dc
CandidateCDHashFull sha256=c46e56e9490d93fe35a76199bdb367b3463c91dcdb3c46403ab8ba1c2d13fd86
Hash choices=sha256
CMSDigest=c46e56e9490d93fe35a76199bdb367b3463c91dcdb3c46403ab8ba1c2d13fd86
CMSDigestType=2
Executable Segment base=0
Executable Segment limit=32768
Executable Segment flags=0x1
Page size=4096
-7=a542b4dcbc134fbd950c230ed9ddb99a343262a2df8e0c847caee2b6d3b41cc8
-6=0000000000000000000000000000000000000000000000000000000000000000
-5=2bb2de519f43b8e116c7eeea8adc6811a276fb134c55c9c2e9dcbd3047f80c7d
-4=0000000000000000000000000000000000000000000000000000000000000000
-3=0000000000000000000000000000000000000000000000000000000000000000
-2=4ca453dc8908dc7f6e637d6159c8761124ae56d080a4a550ad050c27ead273b3
-1=0000000000000000000000000000000000000000000000000000000000000000
0=a5e6478f89812c0c09f123524cad560a9bf758d16014b586089ddc93f004e39c
1=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
2=93d476eeace15a5ad14c0fb56169fd080a04b99582b4c7a01e1afcbc58688f
[...]

# Calculate the hasehs of each page manually
BINARY=/bin/ps
SIZE=`stat -f "%Z" $BINARY`
PAGESIZE=4096 # From the previous output
PAGES=`expr $SIZE / $PAGESIZE`
for i in `seq 0 $PAGES`; do
dd if=$BINARY of=/tmp/`basename $BINARY`.page.$i bs=$PAGESIZE skip=$i count=1
done
openssl sha256 /tmp/*.page.*
```
## Entitlements Blob

Σημειώστε ότι οι εφαρμογές μπορεί επίσης να περιέχουν ένα **entitlement blob** όπου ορίζονται όλα τα δικαιώματα. Επιπλέον, ορισμένα iOS binaries μπορεί να έχουν τα δικαιώματά τους συγκεκριμένα στη ειδική υποδοχή -7 (αντί για την ειδική υποδοχή -5).

## Special Slots

Οι εφαρμογές MacOS δεν έχουν όλα όσα χρειάζονται για να εκτελούνται μέσα στο binary αλλά χρησιμοποιούν επίσης **εξωτερικούς πόρους** (συνήθως μέσα στο **bundle** των εφαρμογών). Επομένως, υπάρχουν ορισμένες υποδοχές μέσα στο binary που θα περιέχουν τα hashes ορισμένων ενδιαφέροντων εξωτερικών πόρων για να ελέγξουν ότι δεν έχουν τροποποιηθεί.

Στην πραγματικότητα, είναι δυνατόν να δούμε στις δομές του Code Directory μια παράμετρο που ονομάζεται **`nSpecialSlots`** που υποδεικνύει τον αριθμό των ειδικών υποδοχών. Δεν υπάρχει ειδική υποδοχή 0 και οι πιο κοινές (από -1 έως -6) είναι:

* Hash του `info.plist` (ή του μέσα στο `__TEXT.__info__plist`).
* Hash των Απαιτήσεων
* Hash του Resource Directory (hash του αρχείου `_CodeSignature/CodeResources` μέσα στο bundle).
* Ειδικό για την εφαρμογή (μη χρησιμοποιούμενο)
* Hash των δικαιωμάτων
* Μόνο υπογραφές κώδικα DMG
* DER Entitlements

## Code Signing Flags

Κάθε διαδικασία έχει σχετιζόμενο ένα bitmask γνωστό ως `status` που ξεκινά από τον πυρήνα και ορισμένα από αυτά μπορούν να παρακαμφθούν από την **υπογραφή κώδικα**. Αυτές οι σημαίες που μπορούν να περιληφθούν στην υπογραφή κώδικα είναι [ορισμένες στον κώδικα](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):
```c
/* code signing attributes of a process */
#define CS_VALID                    0x00000001  /* dynamically valid */
#define CS_ADHOC                    0x00000002  /* ad hoc signed */
#define CS_GET_TASK_ALLOW           0x00000004  /* has get-task-allow entitlement */
#define CS_INSTALLER                0x00000008  /* has installer entitlement */

#define CS_FORCED_LV                0x00000010  /* Library Validation required by Hardened System Policy */
#define CS_INVALID_ALLOWED          0x00000020  /* (macOS Only) Page invalidation allowed by task port policy */

#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION         0x00000400  /* force expiration checking */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */

#define CS_ENFORCEMENT              0x00001000  /* require enforcement */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED   0x00004000  /* code signature permits restricted entitlements */
#define CS_NVRAM_UNRESTRICTED       0x00008000  /* has com.apple.rootless.restricted-nvram-variables.heritable entitlement */

#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
#define CS_LINKER_SIGNED            0x00020000  /* Automatically signed by the linker */

#define CS_ALLOWED_MACHO            (CS_ADHOC | CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | \
CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV | CS_RUNTIME | CS_LINKER_SIGNED)

#define CS_EXEC_SET_HARD            0x00100000  /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL            0x00200000  /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT     0x00400000  /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_INHERIT_SIP         0x00800000  /* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED                   0x01000000  /* was killed by kernel for invalidity */
#define CS_NO_UNTRUSTED_HELPERS     0x02000000  /* kernel did not load a non-platform-binary dyld or Rosetta runtime */
#define CS_DYLD_PLATFORM            CS_NO_UNTRUSTED_HELPERS /* old name */
#define CS_PLATFORM_BINARY          0x04000000  /* this is a platform binary */
#define CS_PLATFORM_PATH            0x08000000  /* platform binary by the fact of path (osx only) */

#define CS_DEBUGGED                 0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define CS_SIGNED                   0x20000000  /* process has a signature (may have gone invalid) */
#define CS_DEV_CODE                 0x40000000  /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */
#define CS_DATAVAULT_CONTROLLER     0x80000000  /* has Data Vault controller entitlement */

#define CS_ENTITLEMENT_FLAGS        (CS_GET_TASK_ALLOW | CS_INSTALLER | CS_DATAVAULT_CONTROLLER | CS_NVRAM_UNRESTRICTED)
```
Note that the function [**exec\_mach\_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) μπορεί επίσης να προσθέσει τις σημαίες `CS_EXEC_*` δυναμικά κατά την εκκίνηση της εκτέλεσης.

## Απαιτήσεις Υπογραφής Κώδικα

Κάθε εφαρμογή αποθηκεύει κάποιες **απαιτήσεις** που πρέπει να **ικανοποιούνται** προκειμένου να μπορεί να εκτελείται. Αν οι **απαιτήσεις της εφαρμογής δεν ικανοποιούνται από την εφαρμογή**, δεν θα εκτελείται (καθώς πιθανώς έχει τροποποιηθεί).

Οι απαιτήσεις ενός δυαδικού αρχείου χρησιμοποιούν μια **ειδική γραμματική** που είναι μια ροή **εκφράσεων** και κωδικοποιούνται ως blobs χρησιμοποιώντας το `0xfade0c00` ως το μαγικό, του οποίου το **hash αποθηκεύεται σε μια ειδική θέση κώδικα**.

Οι απαιτήσεις ενός δυαδικού αρχείου μπορούν να δουν εκτελώντας:

{% code overflow="wrap" %}
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
{% endcode %}

{% hint style="info" %}
Σημειώστε πώς αυτές οι υπογραφές μπορούν να ελέγξουν πράγματα όπως πληροφορίες πιστοποίησης, TeamID, IDs, δικαιώματα και πολλά άλλα δεδομένα.
{% endhint %}

Επιπλέον, είναι δυνατόν να δημιουργηθούν κάποιες συμπιεσμένες απαιτήσεις χρησιμοποιώντας το εργαλείο `csreq`:

{% code overflow="wrap" %}
```bash
# Generate compiled requirements
csreq -b /tmp/output.csreq -r='identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR'

# Get the compiled bytes
od -A x -t x1 /tmp/output.csreq
0000000    fa  de  0c  00  00  00  00  b0  00  00  00  01  00  00  00  06
0000010    00  00  00  06  00  00  00  06  00  00  00  06  00  00  00  02
0000020    00  00  00  21  6f  72  67  2e  77  68  69  73  70  65  72  73
[...]
```
{% endcode %}

Είναι δυνατόν να αποκτήσετε πρόσβαση σε αυτές τις πληροφορίες και να δημιουργήσετε ή να τροποποιήσετε απαιτήσεις με ορισμένα APIs από το `Security.framework` όπως:

#### **Έλεγχος Εγκυρότητας**

* **`Sec[Static]CodeCheckValidity`**: Ελέγχει την εγκυρότητα του SecCodeRef ανά Απαίτηση.
* **`SecRequirementEvaluate`**: Επικυρώνει την απαίτηση στο πλαίσιο του πιστοποιητικού.
* **`SecTaskValidateForRequirement`**: Επικυρώνει μια εκτελούμενη SecTask έναντι της απαίτησης `CFString`.

#### **Δημιουργία και Διαχείριση Απαιτήσεων Κωδικοποίησης**

* **`SecRequirementCreateWithData`:** Δημιουργεί ένα `SecRequirementRef` από δυαδικά δεδομένα που αντιπροσωπεύουν την απαίτηση.
* **`SecRequirementCreateWithString`:** Δημιουργεί ένα `SecRequirementRef` από μια συμβολοσειρά έκφρασης της απαίτησης.
* **`SecRequirementCopy[Data/String]`**: Ανακτά την δυαδική αναπαράσταση δεδομένων ενός `SecRequirementRef`.
* **`SecRequirementCreateGroup`**: Δημιουργεί μια απαίτηση για την ιδιότητα μέλους ομάδας εφαρμογών.

#### **Πρόσβαση σε Πληροφορίες Υπογραφής Κωδικού**

* **`SecStaticCodeCreateWithPath`**: Αρχικοποιεί ένα αντικείμενο `SecStaticCodeRef` από μια διαδρομή συστήματος αρχείων για την επιθεώρηση υπογραφών κωδικού.
* **`SecCodeCopySigningInformation`**: Αποκτά πληροφορίες υπογραφής από ένα `SecCodeRef` ή `SecStaticCodeRef`.

#### **Τροποποίηση Απαιτήσεων Κωδικοποίησης**

* **`SecCodeSignerCreate`**: Δημιουργεί ένα αντικείμενο `SecCodeSignerRef` για την εκτέλεση λειτουργιών υπογραφής κωδικού.
* **`SecCodeSignerSetRequirement`**: Ορίζει μια νέα απαίτηση για τον υπογράφοντα κωδικό να εφαρμόσει κατά την υπογραφή.
* **`SecCodeSignerAddSignature`**: Προσθέτει μια υπογραφή στον κωδικό που υπογράφεται με τον καθορισμένο υπογράφοντα.

#### **Επικύρωση Κωδικού με Απαιτήσεις**

* **`SecStaticCodeCheckValidity`**: Επικυρώνει ένα στατικό αντικείμενο κωδικού έναντι καθορισμένων απαιτήσεων.

#### **Επιπλέον Χρήσιμα APIs**

* **`SecCodeCopy[Internal/Designated]Requirement`: Λάβετε SecRequirementRef από SecCodeRef**
* **`SecCodeCopyGuestWithAttributes`**: Δημιουργεί ένα `SecCodeRef` που αντιπροσωπεύει ένα αντικείμενο κωδικού με βάση συγκεκριμένα χαρακτηριστικά, χρήσιμο για sandboxing.
* **`SecCodeCopyPath`**: Ανακτά τη διαδρομή συστήματος αρχείων που σχετίζεται με ένα `SecCodeRef`.
* **`SecCodeCopySigningIdentifier`**: Αποκτά τον αναγνωριστικό υπογραφής (π.χ., Team ID) από ένα `SecCodeRef`.
* **`SecCodeGetTypeID`**: Επιστρέφει τον αναγνωριστικό τύπου για αντικείμενα `SecCodeRef`.
* **`SecRequirementGetTypeID`**: Λαμβάνει ένα CFTypeID ενός `SecRequirementRef`.

#### **Σημαίες και Σταθερές Υπογραφής Κωδικού**

* **`kSecCSDefaultFlags`**: Προεπιλεγμένες σημαίες που χρησιμοποιούνται σε πολλές λειτουργίες του Security.framework για λειτουργίες υπογραφής κωδικού.
* **`kSecCSSigningInformation`**: Σημαία που χρησιμοποιείται για να καθορίσει ότι οι πληροφορίες υπογραφής πρέπει να ανακτηθούν.

## Επιβολή Υπογραφής Κωδικού

Ο **kernel** είναι αυτός που **ελέγχει την υπογραφή κωδικού** πριν επιτρέψει την εκτέλεση του κωδικού της εφαρμογής. Επιπλέον, ένας τρόπος για να μπορείτε να γράφετε και να εκτελείτε νέο κωδικό στη μνήμη είναι η κατάχρηση του JIT εάν η `mprotect` καλείται με τη σημαία `MAP_JIT`. Σημειώστε ότι η εφαρμογή χρειάζεται μια ειδική εξουσιοδότηση για να μπορεί να το κάνει αυτό.

## `cs_blobs` & `cs_blob`

[**cs\_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) δομή περιέχει τις πληροφορίες σχετικά με την εξουσιοδότηση της εκτελούμενης διαδικασίας σε αυτήν. Το `csb_platform_binary` ενημερώνει επίσης αν η εφαρμογή είναι μια πλατφόρμα δυαδικό (το οποίο ελέγχεται σε διάφορες στιγμές από το OS για να εφαρμόσει μηχανισμούς ασφαλείας όπως η προστασία των δικαιωμάτων SEND στους θύρες εργασίας αυτών των διαδικασιών).
```c
struct cs_blob {
struct cs_blob  *csb_next;
vnode_t         csb_vnode;
void            *csb_ro_addr;
__xnu_struct_group(cs_cpu_info, csb_cpu_info, {
cpu_type_t      csb_cpu_type;
cpu_subtype_t   csb_cpu_subtype;
});
__xnu_struct_group(cs_signer_info, csb_signer_info, {
unsigned int    csb_flags;
unsigned int    csb_signer_type;
});
off_t           csb_base_offset;        /* Offset of Mach-O binary in fat binary */
off_t           csb_start_offset;       /* Blob coverage area start, from csb_base_offset */
off_t           csb_end_offset;         /* Blob coverage area end, from csb_base_offset */
vm_size_t       csb_mem_size;
vm_offset_t     csb_mem_offset;
void            *csb_mem_kaddr;
unsigned char   csb_cdhash[CS_CDHASH_LEN];
const struct cs_hash  *csb_hashtype;
#if CONFIG_SUPPLEMENTAL_SIGNATURES
unsigned char   csb_linkage[CS_CDHASH_LEN];
const struct cs_hash  *csb_linkage_hashtype;
#endif
int             csb_hash_pageshift;
int             csb_hash_firstlevel_pageshift;   /* First hash this many bytes, then hash the hashes together */
const CS_CodeDirectory *csb_cd;
const char      *csb_teamid;
#if CONFIG_SUPPLEMENTAL_SIGNATURES
char            *csb_supplement_teamid;
#endif
const CS_GenericBlob *csb_entitlements_blob;    /* raw blob, subrange of csb_mem_kaddr */
const CS_GenericBlob *csb_der_entitlements_blob;    /* raw blob, subrange of csb_mem_kaddr */

/*
* OSEntitlements pointer setup by AMFI. This is PAC signed in addition to the
* cs_blob being within RO-memory to prevent modifications on the temporary stack
* variable used to setup the blob.
*/
void *XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_entitlements") csb_entitlements;

unsigned int    csb_reconstituted;      /* signature has potentially been modified after validation */
__xnu_struct_group(cs_blob_platform_flags, csb_platform_flags, {
/* The following two will be replaced by the csb_signer_type. */
unsigned int    csb_platform_binary:1;
unsigned int    csb_platform_path:1;
});

/* Validation category used for TLE */
unsigned int    csb_validation_category;

#if CODE_SIGNING_MONITOR
void *XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_csm_obj") csb_csm_obj;
bool csb_csm_managed;
#endif
};
```
## Αναφορές

* [**\*OS Εσωτερικά Τόμος III**](https://newosxbook.com/home.html)

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Εκπαίδευση AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Εκπαίδευση GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
