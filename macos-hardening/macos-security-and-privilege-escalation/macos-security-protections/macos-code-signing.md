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

## 基本情報

Mach-o バイナリには、バイナリ内の署名の **オフセット** と **サイズ** を示す **`LC_CODE_SIGNATURE`** というロードコマンドが含まれています。実際、GUIツールの MachOView を使用すると、バイナリの最後にこの情報を含む **Code Signature** というセクションを見つけることができます：

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Code Signature のマジックヘッダーは **`0xFADE0CC0`** です。次に、これらを含む superBlob の長さや blob の数などの情報があります。\
この情報は、[こちらのソースコード](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs\_blobs.h#L276) で見つけることができます：
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
一般的に含まれるブロブは、コードディレクトリ、要件、権限、および暗号化メッセージ構文（CMS）です。\
さらに、ブロブにエンコードされたデータは**ビッグエンディアン**でエンコードされていることに注意してください。

さらに、署名はバイナリから切り離され、`/var/db/DetachedSignatures`に保存される可能性があります（iOSで使用されます）。

## コードディレクトリブロブ

[コードディレクトリブロブの宣言をコード内で見つけることができます](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs\_blobs.h#L104):
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
注意すべきは、この構造体の異なるバージョンがあり、古いものは情報が少ない場合があることです。

## コード署名ページ

完全なバイナリをハッシュ化することは非効率的であり、部分的にメモリにロードされている場合には無意味です。したがって、コード署名は実際にはハッシュのハッシュであり、各バイナリページが個別にハッシュ化されます。\
実際、前の**コードディレクトリ**コードでは、**ページサイズが指定されている**のがわかります。さらに、バイナリのサイズがページのサイズの倍数でない場合、フィールド**CodeLimit**は署名の終わりがどこにあるかを指定します。
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

アプリケーションにはすべての権限が定義された**権限ブロブ**が含まれている場合があります。さらに、一部のiOSバイナリは、特別なスロット-7に特定の権限を持っている場合があります（-5権限特別スロットの代わりに）。

## Special Slots

MacOSアプリケーションは、バイナリ内で実行するために必要なすべてを持っているわけではなく、**外部リソース**（通常はアプリケーションの**バンドル**内）も使用します。したがって、バイナリ内には、変更されていないことを確認するためにいくつかの興味深い外部リソースのハッシュを含むスロットがあります。

実際、Code Directory構造体には、特別なスロットの数を示す**`nSpecialSlots`**というパラメータがあります。特別なスロット0は存在せず、最も一般的なもの（-1から-6まで）は次のとおりです：

* `info.plist`のハッシュ（または`__TEXT.__info__plist`内のもの）。
* 要件のハッシュ
* リソースディレクトリのハッシュ（バンドル内の`_CodeSignature/CodeResources`ファイルのハッシュ）。
* アプリケーション固有（未使用）
* 権限のハッシュ
* DMGコード署名のみ
* DER権限

## Code Signing Flags

すべてのプロセスには、カーネルによって開始される`status`として知られるビットマスクが関連付けられており、その一部は**コード署名**によって上書きされる可能性があります。コード署名に含めることができるこれらのフラグは[コードで定義されています](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36)：
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
Note that the function [**exec\_mach\_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern\_exec.c#L1420) は、実行を開始する際に `CS_EXEC_*` フラグを動的に追加することもできます。

## コード署名要件

各アプリケーションは、実行可能であるために満たさなければならない **要件** をいくつか **保持** しています。もし **アプリケーションに満たされていない要件が含まれている場合**、それは実行されません（おそらく変更されているためです）。

バイナリの要件は **特別な文法** を使用し、**式** のストリームであり、`0xfade0c00` をマジックとして使用してブロブとしてエンコードされ、その **ハッシュは特別なコードスロットに保存されます**。

バイナリの要件は、次のコマンドを実行することで確認できます：

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
この署名が認証情報、TeamID、ID、権限、その他多くのデータを確認できることに注意してください。
{% endhint %}

さらに、`csreq`ツールを使用していくつかのコンパイルされた要件を生成することが可能です：

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

この情報にアクセスし、`Security.framework`のいくつかのAPIを使用して要件を作成または変更することが可能です：

#### **有効性の確認**

* **`Sec[Static]CodeCheckValidity`**: 要件ごとにSecCodeRefの有効性を確認します。
* **`SecRequirementEvaluate`**: 証明書コンテキスト内の要件を検証します。
* **`SecTaskValidateForRequirement`**: 実行中のSecTaskを`CFString`要件に対して検証します。

#### **コード要件の作成と管理**

* **`SecRequirementCreateWithData`:** 要件を表すバイナリデータから`SecRequirementRef`を作成します。
* **`SecRequirementCreateWithString`:** 要件の文字列表現から`SecRequirementRef`を作成します。
* **`SecRequirementCopy[Data/String]`**: `SecRequirementRef`のバイナリデータ表現を取得します。
* **`SecRequirementCreateGroup`**: アプリグループメンバーシップのための要件を作成します。

#### **コード署名情報へのアクセス**

* **`SecStaticCodeCreateWithPath`**: コード署名を検査するためにファイルシステムパスから`SecStaticCodeRef`オブジェクトを初期化します。
* **`SecCodeCopySigningInformation`**: `SecCodeRef`または`SecStaticCodeRef`から署名情報を取得します。

#### **コード要件の変更**

* **`SecCodeSignerCreate`**: コード署名操作を実行するための`SecCodeSignerRef`オブジェクトを作成します。
* **`SecCodeSignerSetRequirement`**: 署名中に適用するための新しい要件をコード署名者に設定します。
* **`SecCodeSignerAddSignature`**: 指定された署名者で署名されるコードに署名を追加します。

#### **要件によるコードの検証**

* **`SecStaticCodeCheckValidity`**: 指定された要件に対して静的コードオブジェクトを検証します。

#### **追加の便利なAPI**

* **`SecCodeCopy[Internal/Designated]Requirement`: SecCodeRefからSecRequirementRefを取得**
* **`SecCodeCopyGuestWithAttributes`**: 特定の属性に基づいてコードオブジェクトを表す`SecCodeRef`を作成し、サンドボックスに役立ちます。
* **`SecCodeCopyPath`**: `SecCodeRef`に関連付けられたファイルシステムパスを取得します。
* **`SecCodeCopySigningIdentifier`**: `SecCodeRef`から署名識別子（例：チームID）を取得します。
* **`SecCodeGetTypeID`**: `SecCodeRef`オブジェクトのタイプ識別子を返します。
* **`SecRequirementGetTypeID`**: `SecRequirementRef`のCFTypeIDを取得します。

#### **コード署名フラグと定数**

* **`kSecCSDefaultFlags`**: コード署名操作のために多くのSecurity.framework関数で使用されるデフォルトフラグです。
* **`kSecCSSigningInformation`**: 署名情報を取得する必要があることを指定するために使用されるフラグです。

## コード署名の強制

**カーネル**は、アプリのコードを実行する前に**コード署名を確認**します。さらに、メモリ内に新しいコードを書き込み実行するための一つの方法は、`mprotect`が`MAP_JIT`フラグで呼び出されることを悪用することです。この操作を行うには、アプリケーションに特別な権限が必要です。

## `cs_blobs` & `cs_blob`

[**cs\_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106)構造体は、実行中のプロセスの権限に関する情報を含んでいます。`csb_platform_binary`は、アプリケーションがプラットフォームバイナリであるかどうかも通知します（これは、これらのプロセスのタスクポートへのSEND権限を保護するためのセキュリティメカニズムを適用するために、OSによって異なるタイミングで確認されます）。
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
## 参考文献

* [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
