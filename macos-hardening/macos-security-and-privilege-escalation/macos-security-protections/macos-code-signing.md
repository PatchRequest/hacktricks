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

Mach-o бінарники містять команду завантаження під назвою **`LC_CODE_SIGNATURE`**, яка вказує на **зсув** та **розмір** підписів всередині бінарника. Насправді, використовуючи графічний інструмент MachOView, можна знайти в кінці бінарника секцію під назвою **Code Signature** з цією інформацією:

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Магічний заголовок підпису коду - **`0xFADE0CC0`**. Потім ви отримуєте інформацію, таку як довжина та кількість блобів суперBlob, які їх містять.\
Цю інформацію можна знайти в [джерельному коді тут](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs\_blobs.h#L276):
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
Звичайні об'єкти, що містяться, - це Директорія коду, Вимоги та Права, а також Криптографічний синтаксис повідомлень (CMS).\
Крім того, зверніть увагу, як дані, закодовані в об'єктах, закодовані в **Big Endian.**

Крім того, підписи можуть бути відокремлені від бінарних файлів і зберігатися в `/var/db/DetachedSignatures` (використовується iOS).

## Об'єкт директорії коду

Можна знайти оголошення [Об'єкта директорії коду в коді](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs\_blobs.h#L104):
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
Зверніть увагу, що існують різні версії цієї структури, де старі можуть містити менше інформації.

## Сторінки підпису коду

Хешування повного бінарного файлу було б неефективним і навіть марним, якщо він завантажений в пам'ять лише частково. Тому підпис коду насправді є хешем хешів, де кожна бінарна сторінка хешується окремо.\
Насправді, у попередньому коді **Code Directory** ви можете побачити, що **розмір сторінки вказано** в одному з його полів. Більше того, якщо розмір бінарного файлу не є кратним розміру сторінки, поле **CodeLimit** вказує, де закінчується підпис.
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

Зверніть увагу, що програми можуть також містити **entitlement blob**, де визначені всі права. Більше того, деякі бінарні файли iOS можуть мати свої права, специфічні для спеціального слота -7 (замість спеціального слота -5).

## Special Slots

MacOS програми не мають всього необхідного для виконання всередині бінарного файлу, але також використовують **зовнішні ресурси** (зазвичай всередині **bundle** програми). Тому в бінарному файлі є кілька слотів, які міститимуть хеші деяких цікавих зовнішніх ресурсів, щоб перевірити, чи не були вони змінені.

Насправді, в структурах Code Directory можна побачити параметр під назвою **`nSpecialSlots`**, що вказує на кількість спеціальних слотів. Спеціального слота 0 немає, а найпоширеніші (з -1 до -6) це:

* Хеш `info.plist` (або той, що всередині `__TEXT.__info__plist`).
* Хеш вимог
* Хеш каталогу ресурсів (хеш файлу `_CodeSignature/CodeResources` всередині bundle).
* Специфічний для програми (не використовується)
* Хеш прав
* Тільки DMG підписи коду
* DER Entitlements

## Code Signing Flags

Кожен процес має пов'язану бітову маску, відому як `status`, яка ініціюється ядром, і деякі з них можуть бути переозначені **підписом коду**. Ці прапори, які можуть бути включені в підпис коду, [визначені в коді](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):
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
Note that the function [**exec\_mach\_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern\_exec.c#L1420) can also add the `CS_EXEC_*` flags dynamically when starting the execution.

## Вимоги до підпису коду

Кожен додаток зберігає деякі **вимоги**, які він повинен **виконати**, щоб мати можливість виконуватися. Якщо **додаток містить вимоги, які не виконуються додатком**, він не буде виконаний (оскільки, ймовірно, був змінений).

Вимоги бінарного файлу використовують **спеціальну граматику**, яка є потоком **виразів** і кодуються як блоби, використовуючи `0xfade0c00` як магічне число, чий **хеш зберігається в спеціальному кодовому слоті**.

Вимоги бінарного файлу можна побачити, запустивши:

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
Зверніть увагу, як ці підписи можуть перевіряти такі речі, як інформація про сертифікацію, TeamID, ID, права доступу та багато інших даних.
{% endhint %}

Крім того, можливо згенерувати деякі скомпільовані вимоги, використовуючи інструмент `csreq`:

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

Можливо отримати цю інформацію та створити або змінити вимоги за допомогою деяких API з `Security.framework`, таких як:

#### **Перевірка дійсності**

* **`Sec[Static]CodeCheckValidity`**: Перевіряє дійсність SecCodeRef відповідно до вимоги.
* **`SecRequirementEvaluate`**: Валідовує вимогу в контексті сертифіката.
* **`SecTaskValidateForRequirement`**: Валідовує запущений SecTask відповідно до вимоги `CFString`.

#### **Створення та управління вимогами коду**

* **`SecRequirementCreateWithData`:** Створює `SecRequirementRef` з бінарних даних, що представляють вимогу.
* **`SecRequirementCreateWithString`:** Створює `SecRequirementRef` з рядкової виразу вимоги.
* **`SecRequirementCopy[Data/String]`**: Отримує бінарне представлення даних `SecRequirementRef`.
* **`SecRequirementCreateGroup`**: Створює вимогу для членства в групі додатків.

#### **Доступ до інформації про підпис коду**

* **`SecStaticCodeCreateWithPath`**: Ініціалізує об'єкт `SecStaticCodeRef` з файлового шляху для перевірки підписів коду.
* **`SecCodeCopySigningInformation`**: Отримує інформацію про підпис з `SecCodeRef` або `SecStaticCodeRef`.

#### **Модифікація вимог коду**

* **`SecCodeSignerCreate`**: Створює об'єкт `SecCodeSignerRef` для виконання операцій підпису коду.
* **`SecCodeSignerSetRequirement`**: Встановлює нову вимогу для підписувача коду, яку потрібно застосувати під час підпису.
* **`SecCodeSignerAddSignature`**: Додає підпис до коду, що підписується, з вказаним підписувачем.

#### **Валідуючи код з вимогами**

* **`SecStaticCodeCheckValidity`**: Валідовує статичний об'єкт коду відповідно до вказаних вимог.

#### **Додаткові корисні API**

* **`SecCodeCopy[Internal/Designated]Requirement`: Отримати SecRequirementRef з SecCodeRef**
* **`SecCodeCopyGuestWithAttributes`**: Створює `SecCodeRef`, що представляє об'єкт коду на основі специфічних атрибутів, корисно для пісочниці.
* **`SecCodeCopyPath`**: Отримує файловий шлях, пов'язаний з `SecCodeRef`.
* **`SecCodeCopySigningIdentifier`**: Отримує ідентифікатор підпису (наприклад, Team ID) з `SecCodeRef`.
* **`SecCodeGetTypeID`**: Повертає ідентифікатор типу для об'єктів `SecCodeRef`.
* **`SecRequirementGetTypeID`**: Отримує CFTypeID `SecRequirementRef`.

#### **Прапори та константи підпису коду**

* **`kSecCSDefaultFlags`**: Значення за замовчуванням, що використовуються в багатьох функціях Security.framework для операцій підпису коду.
* **`kSecCSSigningInformation`**: Прапор, що використовується для вказівки на те, що інформація про підпис повинна бути отримана.

## Примус підпису коду

**Ядро** є тим, хто **перевіряє підпис коду** перед тим, як дозволити виконання коду додатка. Більше того, один зі способів мати можливість записувати та виконувати новий код в пам'яті - це зловживання JIT, якщо `mprotect` викликано з прапором `MAP_JIT`. Зверніть увагу, що додаток потребує спеціального права, щоб мати можливість це робити.

## `cs_blobs` & `cs_blob`

[**cs\_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc\_internal.h#L106) структура містить інформацію про права запущеного процесу на ньому. `csb_platform_binary` також інформує, чи є додаток платформним бінарним (що перевіряється в різні моменти ОС для застосування механізмів безпеки, таких як захист прав SEND до портів завдань цих процесів).
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
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
