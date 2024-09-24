# macOS Sandbox

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

MacOS Sandbox (awali ilijulikana kama Seatbelt) **inaweka mipaka kwa programu** zinazotembea ndani ya sandbox kwa **vitendo vilivyokubaliwa vilivyobainishwa katika profaili ya Sandbox** ambayo programu inatumia. Hii husaidia kuhakikisha kwamba **programu itakuwa inapata rasilimali zinazotarajiwa tu**.

Programu yoyote yenye **entitlement** **`com.apple.security.app-sandbox`** itatekelezwa ndani ya sandbox. **Apple binaries** kwa kawaida hutekelezwa ndani ya Sandbox, na programu zote kutoka **App Store zina entitlement hiyo**. Hivyo, programu kadhaa zitatekelezwa ndani ya sandbox.

Ili kudhibiti kile mchakato unaweza au hawezi kufanya, **Sandbox ina hooks** katika karibu kila operesheni ambayo mchakato unaweza kujaribu (ikiwemo syscalls nyingi) kwa kutumia **MACF**. Hata hivyo, **kutegemea** na **entitlements** za programu, Sandbox inaweza kuwa na uvumilivu zaidi kwa mchakato.

Baadhi ya vipengele muhimu vya Sandbox ni:

* **kernel extension** `/System/Library/Extensions/Sandbox.kext`
* **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* **daemon** inayotembea katika userland `/usr/libexec/sandboxd`
* **containers** `~/Library/Containers`

### Containers

Kila programu iliyowekwa sandbox itakuwa na kontena yake mwenyewe katika `~/Library/Containers/{CFBundleIdentifier}` :
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Ndani ya kila folda ya bundle id unaweza kupata **plist** na **Data directory** ya App yenye muundo unaofanana na folda ya Nyumbani:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
Kumbuka kwamba hata kama symlinks zipo ili "kutoroka" kutoka Sandbox na kufikia folda nyingine, App bado inahitaji **kuwa na ruhusa** za kuzifikia. Ruhusa hizi ziko ndani ya **`.plist`** katika `RedirectablePaths`.
{% endhint %}

The **`SandboxProfileData`** is the compiled sandbox profile CFData escaped to B64.
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Kila kitu kilichoundwa/kilibadilishwa na programu ya Sandboxed kitapata **sifa ya karantini**. Hii itazuia nafasi ya sandbox kwa kuanzisha Gatekeeper ikiwa programu ya sandbox inajaribu kutekeleza kitu kwa kutumia **`open`**.
{% endhint %}

## Profaili za Sandbox

Profaili za Sandbox ni faili za usanidi zinazoonyesha kile kitakachokuwa **kuruhusiwa/kukatazwa** katika hiyo **Sandbox**. Inatumia **Sandbox Profile Language (SBPL)**, ambayo inatumia lugha ya programu ya [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

Hapa unaweza kupata mfano:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
Check this [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **to check more actions that could be allowed or denied.**

Note that in the compiled version of a profile the name of the operations are substituded by their entries in an array known by the dylib and the kext, making the compiled version shorter and more difficult to read.
{% endhint %}

Important **huduma za mfumo** also run inside their own custom **sandbox** such as the `mdnsresponder` service. You can view these custom **sandbox profiles** inside:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**
* Other sandbox profiles can be checked in [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

**App Store** apps use the **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. You can check in this profile how entitlements such as **`com.apple.security.network.server`** allows a process to use the network.

SIP is a Sandbox profile called platform\_profile in /System/Library/Sandbox/rootless.conf

### Sandbox Profile Examples

To start an application with an **specific sandbox profile** you can use:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% endcode %}

{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Kumbuka kwamba **programu** **iliyoundwa na Apple** inayofanya kazi kwenye **Windows** **haina tahadhari za ziada za usalama**, kama vile sandboxing ya programu.
{% endhint %}

Mifano ya kupita:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (wanaweza kuandika faili nje ya sandbox ambayo jina lake linaanza na `~$`).

### Ufuatiliaji wa Sandbox

#### Kupitia profaili

Inawezekana kufuatilia ukaguzi wote sandbox inafanya kila wakati kitendo kinapokaguliwa. Kwa hivyo, tengeneza profaili ifuatayo:

{% code title="trace.sb" %}
```scheme
(version 1)
(trace /tmp/trace.out)
```
{% endcode %}

Kisha tekeleza kitu chochote ukitumia profaili hiyo:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
In `/tmp/trace.out` utaweza kuona kila ukaguzi wa sandbox uliofanywa kila wakati ulipokuwa ukitolewa (hivyo, kuna nakala nyingi).

Pia inawezekana kufuatilia sandbox kwa kutumia **`-t`** parameter: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Kupitia API

Kazi `sandbox_set_trace_path` iliyotolewa na `libsystem_sandbox.dylib` inaruhusu kuweka jina la faili la kufuatilia ambapo ukaguzi wa sandbox utaandikwa.\
Pia inawezekana kufanya kitu kama hicho kwa kuita `sandbox_vtrace_enable()` na kisha kupata makosa ya log kutoka kwenye buffer kwa kuita `sandbox_vtrace_report()`.

### Ukaguzi wa Sandbox

`libsandbox.dylib` inatoa kazi inayoitwa sandbox\_inspect\_pid ambayo inatoa orodha ya hali ya sandbox ya mchakato (ikiwemo nyongeza). Hata hivyo, ni binaries za jukwaa pekee ndizo zinaweza kutumia kazi hii.

### MacOS & iOS Sandbox Profiles

MacOS inahifadhi wasifu wa sandbox wa mfumo katika maeneo mawili: **/usr/share/sandbox/** na **/System/Library/Sandbox/Profiles**.

Na ikiwa programu ya upande wa tatu ina _**com.apple.security.app-sandbox**_ ruhusa, mfumo unatumia wasifu **/System/Library/Sandbox/Profiles/application.sb** kwa mchakato huo.

Katika iOS, wasifu wa kawaida unaitwa **container** na hatuna uwakilishi wa maandiko wa SBPL. Katika kumbukumbu, sandbox hii inawakilishwa kama mti wa binary wa Ruhusu/Kataa kwa kila ruhusa kutoka sandbox.

### SBPL Maalum katika programu za App Store

Inaweza kuwa inawezekana kwa kampuni kufanya programu zao zifanye kazi **na wasifu wa Sandbox maalum** (badala ya wa kawaida). Wanahitaji kutumia ruhusa **`com.apple.security.temporary-exception.sbpl`** ambayo inahitaji kuidhinishwa na Apple.

Inawezekana kuangalia ufafanuzi wa ruhusa hii katika **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
This will **eval the string after this entitlement** as an Sandbox profile.

### Compiling & decompiling a Sandbox Profile

The **`sandbox-exec`** tool uses the functions `sandbox_compile_*` from `libsandbox.dylib`. The main functions exported are: `sandbox_compile_file` (inatarajia njia ya faili, param `-f`), `sandbox_compile_string` (inatarajia string, param `-p`), `sandbox_compile_name` (inatarajia jina la kontena, param `-n`), `sandbox_compile_entitlements` (inatarajia entitlements plist).

This reversed and [**open sourced version of the tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings\&file=/sandbox\_exec.c) allows to make **`sandbox-exec`** write into a file the compiled sandbox profile.

Moreover, to confine a process inside a container it might call `sandbox_spawnattrs_set[container/profilename]` and pass a container or pre-existing profile.

## Debug & Bypass Sandbox

On macOS, unlike iOS where processes are sandboxed from the start by the kernel, **processes must opt-in to the sandbox themselves**. This means on macOS, a process is not restricted by the sandbox until it actively decides to enter it, although App Store apps are always sandboxed.

Processes are automatically Sandboxed from userland when they start if they have the entitlement: `com.apple.security.app-sandbox`. For a detailed explanation of this process check:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

## **Sandbox Extensions**

Extensions allow to give further privileges to an object and are giving calling one of the functions:

* `sandbox_issue_extension`
* `sandbox_extension_issue_file[_with_new_type]`
* `sandbox_extension_issue_mach`
* `sandbox_extension_issue_iokit_user_client_class`
* `sandbox_extension_issue_iokit_registry_rentry_class`
* `sandbox_extension_issue_generic`
* `sandbox_extension_issue_posix_ipc`

The extensions are stored in the second MACF label slot accessible from the process credentials. The following **`sbtool`** can access this information.

Note that extensions are usually granted by allowed processes, for example, `tccd` will grant the extension token of `com.apple.tcc.kTCCServicePhotos` when a process tried to access the photos and was allowed in a XPC message. Then, the process will need to consume the extension token so it gets added to it.\
Note that the extension tokens are long hexadecimals that encode the granted permissions. However they don't have the allowed PID hardcoded which means that any process with access to the token might be **consumed by multiple processes**.

Note that extensions are very related to entitlements also, so having certain entitlements might automatically grant certain extensions.

### **Check PID Privileges**

[**According to this**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), the **`sandbox_check`** functions (it's a `__mac_syscall`), can check **if an operation is allowed or not** by the sandbox in a certain PID, audit token or unique ID.

The [**tool sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) (find it [compiled here](https://newosxbook.com/articles/hitsb.html)) can check if a PID can perform a certain actions:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Inawezekana pia kusitisha na kuondoa kusitishwa kwa sandbox kwa kutumia kazi `sandbox_suspend` na `sandbox_unsuspend` kutoka `libsystem_sandbox.dylib`.

Kumbuka kwamba ili kuita kazi ya kusitisha, haki fulani zinakaguliwa ili kuidhinisha mwitikiaji kuitumia kama:

* com.apple.private.security.sandbox-manager
* com.apple.security.print
* com.apple.security.temporary-exception.audio-unit-host

## mac\_syscall

Kito hiki cha mfumo (#381) kinatarajia hoja ya kwanza ya maandiko ambayo itaonyesha moduli ya kuendesha, na kisha msimbo katika hoja ya pili ambayo itaonyesha kazi ya kuendesha. Kisha, hoja ya tatu itategemea kazi iliyotekelezwa.

Kazi `___sandbox_ms` inafunga `mac_syscall` ikionyesha katika hoja ya kwanza `"Sandbox"` kama vile `___sandbox_msp` ni kifungashio cha `mac_set_proc` (#387). Kisha, baadhi ya misimbo inayoungwa mkono na `___sandbox_ms` inaweza kupatikana katika jedwali hili:

* **set\_profile (#0)**: Tumia wasifu uliokamilishwa au uliotajwa kwa mchakato.
* **platform\_policy (#1)**: Lazimisha ukaguzi wa sera maalum za jukwaa (hubadilika kati ya macOS na iOS).
* **check\_sandbox (#2)**: Fanya ukaguzi wa mkono wa operesheni maalum ya sandbox.
* **note (#3)**: Ongeza anoteshini kwa Sandbox
* **container (#4)**: Unganisha anoteshini kwa sandbox, kawaida kwa ajili ya urekebishaji au utambulisho.
* **extension\_issue (#5)**: Tengeneza nyongeza mpya kwa mchakato.
* **extension\_consume (#6)**: Tumia nyongeza iliyotolewa.
* **extension\_release (#7)**: Achilia kumbukumbu iliyohusishwa na nyongeza iliyotumiwa.
* **extension\_update\_file (#8)**: Badilisha vigezo vya nyongeza ya faili iliyopo ndani ya sandbox.
* **extension\_twiddle (#9)**: Rekebisha au badilisha nyongeza ya faili iliyopo (mfano, TextEdit, rtf, rtfd).
* **suspend (#10)**: Kusitisha kwa muda ukaguzi wote wa sandbox (inahitaji haki zinazofaa).
* **unsuspend (#11)**: Anza tena ukaguzi wote wa sandbox uliositishwa hapo awali.
* **passthrough\_access (#12)**: Ruhusu ufikiaji wa moja kwa moja kwa rasilimali, ukipita ukaguzi wa sandbox.
* **set\_container\_path (#13)**: (iOS pekee) Weka njia ya kontena kwa kikundi cha programu au kitambulisho cha kusaini.
* **container\_map (#14)**: (iOS pekee) Pata njia ya kontena kutoka `containermanagerd`.
* **sandbox\_user\_state\_item\_buffer\_send (#15)**: (iOS 10+) Weka metadata ya hali ya mtumiaji ndani ya sandbox.
* **inspect (#16)**: Toa taarifa za urekebishaji kuhusu mchakato wa sandboxed.
* **dump (#18)**: (macOS 11) Dump wasifu wa sasa wa sandbox kwa ajili ya uchambuzi.
* **vtrace (#19)**: Fuata operesheni za sandbox kwa ajili ya ufuatiliaji au urekebishaji.
* **builtin\_profile\_deactivate (#20)**: (macOS < 11) Zima wasifu uliotajwa (mfano, `pe_i_can_has_debugger`).
* **check\_bulk (#21)**: Fanya operesheni nyingi za `sandbox_check` katika wito mmoja.
* **reference\_retain\_by\_audit\_token (#28)**: Tengeneza rejeleo kwa token ya ukaguzi kwa matumizi katika ukaguzi wa sandbox.
* **reference\_release (#29)**: Achilia rejeleo la token ya ukaguzi iliyoshikiliwa hapo awali.
* **rootless\_allows\_task\_for\_pid (#30)**: Thibitisha ikiwa `task_for_pid` inaruhusiwa (kama `csr` ukaguzi).
* **rootless\_whitelist\_push (#31)**: (macOS) Tumia faili ya orodha ya Ulinzi wa Uadilifu wa Mfumo (SIP).
* **rootless\_whitelist\_check (preflight) (#32)**: Kagua faili ya orodha ya SIP kabla ya utekelezaji.
* **rootless\_protected\_volume (#33)**: (macOS) Tumia ulinzi wa SIP kwa diski au sehemu.
* **rootless\_mkdir\_protected (#34)**: Tumia ulinzi wa SIP/DataVault kwa mchakato wa kuunda saraka.

## Sandbox.kext

Kumbuka kwamba katika iOS, nyongeza ya kernel ina **wasifu wote waliowekwa** ndani ya sehemu ya `__TEXT.__const` ili kuzuia kubadilishwa. Hapa kuna baadhi ya kazi za kuvutia kutoka kwa nyongeza ya kernel:

* **`hook_policy_init`**: Inachanganya `mpo_policy_init` na inaitwa baada ya `mac_policy_register`. Inatekeleza sehemu kubwa ya uanzishaji wa Sandbox. Pia inaanzisha SIP.
* **`hook_policy_initbsd`**: Inatayarisha interface ya sysctl ikijiandikisha `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` na `security.mac.sandbox.debug_mode` (ikiwa imebood na `PE_i_can_has_debugger`).
* **`hook_policy_syscall`**: Inaitwa na `mac_syscall` ikiwa na "Sandbox" kama hoja ya kwanza na msimbo unaoashiria operesheni katika ya pili. Switch inatumika kupata msimbo wa kuendesha kulingana na msimbo uliotakiwa.

### MACF Hooks

**`Sandbox.kext`** inatumia zaidi ya mia moja ya hooks kupitia MACF. Mengi ya hooks haya yatakagua tu hali fulani za kawaida ambazo zinaruhusu kutekeleza kitendo, ikiwa sivyo, zitaita **`cred_sb_evalutate`** na **vigezo** kutoka MACF na nambari inayohusiana na **operesheni** ya kutekeleza na **buffer** kwa ajili ya matokeo.

Mfano mzuri wa hiyo ni kazi **`_mpo_file_check_mmap`** ambayo inachanganya **`mmap`** na ambayo itaanza kuangalia ikiwa kumbukumbu mpya itakuwa na uwezo wa kuandikwa (na ikiwa sivyo ruhusu utekelezaji), kisha itakagua ikiwa inatumika kwa cache ya pamoja ya dyld na ikiwa ndivyo ruhusu utekelezaji, na hatimaye itaita **`cred_sb_evalutate`** ili kufanya ukaguzi zaidi wa ruhusa.

Zaidi ya hayo, kati ya mia kadhaa ya hooks ambazo Sandbox inatumia, kuna 3 kwa hasa ambazo ni za kuvutia sana:

* `mpo_proc_check_for`: Inatumia wasifu ikiwa inahitajika na ikiwa haijatumika hapo awali
* `mpo_vnode_check_exec`: Inaitwa wakati mchakato unapoleta binary inayohusiana, kisha ukaguzi wa wasifu unafanywa na pia ukaguzi unaozuia utekelezaji wa SUID/SGID.
* `mpo_cred_label_update_execve`: Hii inaitwa wakati lebo inatolewa. Hii ni ndefu zaidi kwani inaitwa wakati binary imepakiwa kikamilifu lakini haijatekelezwa bado. Itatekeleza vitendo kama kuunda kitu cha sandbox, kuunganisha muundo wa sandbox kwa vigezo vya kauth, kuondoa ufikiaji wa mach ports...

Kumbuka kwamba **`cred_sb_evalutate`** ni kifungashio juu ya **`sb_evaluate`** na kazi hii inapata vigezo vilivyopitishwa na kisha inatekeleza tathmini kwa kutumia kazi ya **`eval`** ambayo kawaida inakagua **wasifu wa jukwaa** ambao kwa default unatumika kwa mchakato wote na kisha **wasifu maalum wa mchakato**. Kumbuka kwamba wasifu wa jukwaa ni moja ya sehemu kuu za **SIP** katika macOS.

## Sandboxd

Sandbox pia ina daemon ya mtumiaji inayofanya kazi ikionyesha huduma ya XPC Mach `com.apple.sandboxd` na kuunganisha bandari maalum 14 (`HOST_SEATBELT_PORT`) ambayo nyongeza ya kernel inatumia kuwasiliana nayo. Inatoa baadhi ya kazi kwa kutumia MIG.

## References

* [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
