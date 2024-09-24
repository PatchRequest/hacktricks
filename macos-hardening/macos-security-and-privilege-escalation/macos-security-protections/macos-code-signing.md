# macOS Code Signing

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

Mach-o binaries zina maelezo ya kupakia yanayoitwa **`LC_CODE_SIGNATURE`** ambayo yanaonyesha **offset** na **size** ya saini ndani ya binary. Kwa kweli, kwa kutumia zana ya GUI MachOView, inawezekana kupata mwishoni mwa binary sehemu inayoitwa **Code Signature** yenye maelezo haya:

<figure><img src="../../../.gitbook/assets/image (1).png" alt="" width="431"><figcaption></figcaption></figure>

Kichwa cha kichawi cha Code Signature ni **`0xFADE0CC0`**. Kisha una maelezo kama vile urefu na idadi ya blobs ya superBlob inayoyashikilia.\
Inawezekana kupata maelezo haya katika [source code hapa](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs\_blobs.h#L276):
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
Common blobs contained are Code Directory, Requirements and Entitlements and a Cryptographic Message Syntax (CMS).\
Moreover, note how the data encoded in the blobs is encoded in **Big Endian.**

Moreover, signatures zinaweza kutengwa kutoka kwa binaries na kuhifadhiwa katika `/var/db/DetachedSignatures` (inayotumiwa na iOS).

## Code Directory Blob

It's possible to find the declaration of the [Code Directory Blob in the code](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs\_blobs.h#L104):
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
Note that there are different versions of this struct where old ones might contain less information.

## Signing Code Pages

Hashing the full binary would be inefficient and even useless if when it's only loaded in memory partially. Therefore, the code signature is actually a hash of hashes where each binary page is hashed individually.\
Actually, in the previous **Code Directory** code you can see that the **page size is specified** in one of its fields. Moreover, if the size of the binary is not a multiple of the size of a page, the field **CodeLimit** specifies where is the end of the signature.
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

Kumbuka kwamba programu zinaweza pia kuwa na **entitlement blob** ambapo haki zote zinafafanuliwa. Zaidi ya hayo, baadhi ya binaries za iOS zinaweza kuwa na haki zao maalum katika sloti maalum -7 (badala ya katika sloti maalum -5 za haki).

## Special Slots

Programu za MacOS hazina kila kitu wanachohitaji kutekeleza ndani ya binary lakini pia zinatumia **rasilimali za nje** (kawaida ndani ya **bundle** za programu). Hivyo, kuna sloti ndani ya binary ambazo zitakuwa na hash za baadhi ya rasilimali za nje za kuvutia ili kuangalia hazikubadilishwa.

Kwa kweli, inawezekana kuona katika muundo wa Directory ya Code parameter inayoitwa **`nSpecialSlots`** ikionyesha idadi ya sloti maalum. Hakuna sloti maalum 0 na zile zinazotumika zaidi (kutoka -1 hadi -6 ni):

* Hash ya `info.plist` (au ile ndani ya `__TEXT.__info__plist`).
* Hash ya Mahitaji
* Hash ya Directory ya Rasilimali (hash ya faili ya `_CodeSignature/CodeResources` ndani ya bundle).
* Maalum kwa programu (isiyotumika)
* Hash ya haki
* Saini za msimbo wa DMG pekee
* Haki za DER

## Code Signing Flags

Kila mchakato una bitmask inayohusiana inayojulikana kama `status` ambayo inaanzishwa na kernel na baadhi yao zinaweza kubadilishwa na **saini ya msimbo**. Bendera hizi ambazo zinaweza kujumuishwa katika saini ya msimbo zina [fafanuliwa katika msimbo](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):
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
Note that the function [**exec\_mach\_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern\_exec.c#L1420) inaweza pia kuongeza bendera za `CS_EXEC_*` kwa njia ya kidinamik wakati wa kuanza utekelezaji.

## Mahitaji ya Saini ya Kanuni

Kila programu ina **mahitaji** ambayo lazima **iyatimize** ili iweze kutekelezwa. Ikiwa **programu ina mahitaji ambayo hayajatimizwa na programu**, haitatekelezwa (kama imebadilishwa).

Mahitaji ya binary hutumia **sarufi maalum** ambayo ni mtiririko wa **maelezo** na yanakodishwa kama blobs kwa kutumia `0xfade0c00` kama uchawi ambao **hash yake inahifadhiwa katika sloti maalum ya kanuni**.

Mahitaji ya binary yanaweza kuonekana kwa kukimbia: 

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
Kumbuka jinsi saini hizi zinaweza kuangalia mambo kama taarifa za uthibitisho, TeamID, IDs, ruhusa na data nyingine nyingi.
{% endhint %}

Zaidi ya hayo, inawezekana kuzalisha baadhi ya mahitaji yaliyokusanywa kwa kutumia zana ya `csreq`:

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

Inawezekana kufikia habari hii na kuunda au kubadilisha mahitaji na baadhi ya APIs kutoka `Security.framework` kama:

#### **Kuangalia Uhalali**

* **`Sec[Static]CodeCheckValidity`**: Angalia uhalali wa SecCodeRef kwa kila Mahitaji.
* **`SecRequirementEvaluate`**: Thibitisha mahitaji katika muktadha wa cheti.
* **`SecTaskValidateForRequirement`**: Thibitisha SecTask inayotembea dhidi ya mahitaji ya `CFString`.

#### **Kuunda na Kusimamia Mahitaji ya Msimbo**

* **`SecRequirementCreateWithData`:** Inaunda `SecRequirementRef` kutoka kwa data ya binary inayowakilisha mahitaji.
* **`SecRequirementCreateWithString`:** Inaunda `SecRequirementRef` kutoka kwa usemi wa string wa mahitaji.
* **`SecRequirementCopy[Data/String]`**: Inapata uwakilishi wa data ya binary wa `SecRequirementRef`.
* **`SecRequirementCreateGroup`**: Unda mahitaji ya ushirika wa programu.

#### **Kufikia Habari za Kusaini Msimbo**

* **`SecStaticCodeCreateWithPath`**: Inaanzisha kipande cha `SecStaticCodeRef` kutoka kwa njia ya mfumo wa faili kwa ajili ya kukagua saini za msimbo.
* **`SecCodeCopySigningInformation`**: Inapata habari za kusaini kutoka kwa `SecCodeRef` au `SecStaticCodeRef`.

#### **Kubadilisha Mahitaji ya Msimbo**

* **`SecCodeSignerCreate`**: Inaunda kipande cha `SecCodeSignerRef` kwa ajili ya kufanya operesheni za kusaini msimbo.
* **`SecCodeSignerSetRequirement`**: Inaweka mahitaji mapya kwa ajili ya msajili wa msimbo kutekeleza wakati wa kusaini.
* **`SecCodeSignerAddSignature`**: Inaongeza saini kwa msimbo unaosainiwa na msajili aliyeainishwa.

#### **Kuthibitisha Msimbo kwa Mahitaji**

* **`SecStaticCodeCheckValidity`**: Inathibitisha kipande cha msimbo wa static dhidi ya mahitaji yaliyoainishwa.

#### **APIs za Ziada za Faida**

* **`SecCodeCopy[Internal/Designated]Requirement`: Pata SecRequirementRef kutoka SecCodeRef**
* **`SecCodeCopyGuestWithAttributes`**: Inaunda `SecCodeRef` inayowakilisha kipande cha msimbo kulingana na sifa maalum, muhimu kwa sandboxing.
* **`SecCodeCopyPath`**: Inapata njia ya mfumo wa faili inayohusiana na `SecCodeRef`.
* **`SecCodeCopySigningIdentifier`**: Inapata kitambulisho cha kusaini (mfano, Timu ID) kutoka kwa `SecCodeRef`.
* **`SecCodeGetTypeID`**: Inarudisha kitambulisho cha aina kwa ajili ya vitu vya `SecCodeRef`.
* **`SecRequirementGetTypeID`**: Inapata CFTypeID ya `SecRequirementRef`.

#### **Bendera na Misingi ya Kusaini Msimbo**

* **`kSecCSDefaultFlags`**: Bendera za kawaida zinazotumika katika kazi nyingi za Security.framework kwa ajili ya operesheni za kusaini msimbo.
* **`kSecCSSigningInformation`**: Bendera inayotumika kuashiria kwamba habari za kusaini zinapaswa kupatikana.

## Utekelezaji wa Saini ya Msimbo

**Kernel** ndiye anayekagua **saini ya msimbo** kabla ya kuruhusu msimbo wa programu kutekelezwa. Aidha, njia moja ya kuweza kuandika na kutekeleza msimbo mpya katika kumbukumbu ni kutumia JIT ikiwa `mprotect` inaitwa na bendera ya `MAP_JIT`. Kumbuka kwamba programu inahitaji haki maalum ili iweze kufanya hivi.

## `cs_blobs` & `cs_blob`

[**cs\_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc\_internal.h#L106) muundo unashikilia habari kuhusu haki ya mchakato unaotembea juu yake. `csb_platform_binary` pia inaarifu ikiwa programu ni binary ya jukwaa (ambayo inakaguliwa katika nyakati tofauti na OS ili kutekeleza mitambo ya usalama kama kulinda haki za SEND kwa bandari za kazi za michakato hii).
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
## References

* [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}