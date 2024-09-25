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

MacOS Sandbox (aanvanklik Seatbelt genoem) **beperk toepassings** wat binne die sandbox loop na die **toegelate aksies wat in die Sandbox-profiel gespesifiseer is** waarmee die app loop. Dit help om te verseker dat **die toepassing slegs verwagte hulpbronne sal benader**.

Enige app met die **regte** **`com.apple.security.app-sandbox`** sal binne die sandbox uitgevoer word. **Apple-binaries** word gewoonlik binne 'n Sandbox uitgevoer, en alle toepassings van die **App Store het daardie regte**. Dus sal verskeie toepassings binne die sandbox uitgevoer word.

Om te beheer wat 'n proses kan of nie kan doen nie, het die **Sandbox haakplekke** in byna enige operasie wat 'n proses mag probeer (insluitend die meeste syscalls) met behulp van **MACF**. egter, d**epending** op die **regte** van die app mag die Sandbox meer toelaatbaar wees met die proses.

Sommige belangrike komponente van die Sandbox is:

* Die **kernel-uitbreiding** `/System/Library/Extensions/Sandbox.kext`
* Die **privaat raamwerk** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* 'n **daemon** wat in userland loop `/usr/libexec/sandboxd`
* Die **houers** `~/Library/Containers`

### Containers

Elke sandboxed toepassing sal sy eie houer hê in `~/Library/Containers/{CFBundleIdentifier}` :
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
Binne elke bundel-id gids kan jy die **plist** en die **Data-gids** van die App vind met 'n struktuur wat die Huis-gids naboots:
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
Let daarop dat selfs al is die symlinks daar om te "ontsnap" uit die Sandbox en ander mappen te benader, moet die App steeds **toestemmings hê** om toegang tot hulle te verkry. Hierdie toestemmings is binne die **`.plist`** in die `RedirectablePaths`.
{% endhint %}

Die **`SandboxProfileData`** is die gecompileerde sandbox-profiel CFData wat na B64 ontsnap is.
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
Alles wat deur 'n Sandboxed-toepassing geskep/gewysig word, sal die **kwarantynattribuut** ontvang. Dit sal 'n sandbox ruimte voorkom deur Gatekeeper te aktiveer as die sandbox-toepassing probeer om iets met **`open`** uit te voer.
{% endhint %}

## Sandbox Profiele

Die Sandbox profiele is konfigurasie lêers wat aandui wat in daardie **Sandbox** **toegelaat/verbode** gaan wees. Dit gebruik die **Sandbox Profile Language (SBPL)**, wat die [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) programmeertaal gebruik.

Hier kan jy 'n voorbeeld vind:
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
Kontrollere hierdie [**navorsing**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **om meer aksies te kontroleer wat toegelaat of geweier kan word.**

Let daarop dat in die saamgestelde weergawe van 'n profiel die name van die operasies vervang word deur hul inskrywings in 'n array wat deur die dylib en die kext bekend is, wat die saamgestelde weergawe korter en moeiliker leesbaar maak.
{% endhint %}

Belangrike **stelseldienste** loop ook binne hul eie pasgemaakte **sandbox** soos die `mdnsresponder` diens. Jy kan hierdie pasgemaakte **sandbox-profiele** binne kyk:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**
* Ander sandbox-profiele kan nagegaan word in [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

**App Store** programme gebruik die **profiel** **`/System/Library/Sandbox/Profiles/application.sb`**. Jy kan in hierdie profiel kyk hoe regte soos **`com.apple.security.network.server`** 'n proses toelaat om die netwerk te gebruik.

SIP is 'n Sandbox-profiel genaamd platform\_profile in /System/Library/Sandbox/rootless.conf

### Sandbox Profiel Voorbeelde

Om 'n toepassing met 'n **spesifieke sandbox-profiel** te begin, kan jy gebruik maak van:
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
Let daarop dat die **Apple-geskrewe** **programmatuur** wat op **Windows** loop, **nie addisionele sekuriteitsmaatreëls** het nie, soos toepassingsandboxing.
{% endhint %}

Bypasses voorbeelde:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (hulle kan lêers buite die sandbox skryf waarvan die naam met `~$` begin).

### Sandbox Tracing

#### Via profiel

Dit is moontlik om al die kontroles wat die sandbox elke keer wanneer 'n aksie nagegaan word, uit te spoor. Skep net die volgende profiel: 

{% code title="trace.sb" %}
```scheme
(version 1)
(trace /tmp/trace.out)
```
{% endcode %}

En voer dan net iets uit met daardie profiel:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
In `/tmp/trace.out` sal jy in staat wees om elke sandbox kontrole te sien wat uitgevoer is elke keer dit aangeroep is (dus, baie duplikate).

Dit is ook moontlik om die sandbox te volg met die **`-t`** parameter: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

Die funksie `sandbox_set_trace_path` wat deur `libsystem_sandbox.dylib` uitgevoer word, laat jou toe om 'n trace lêernaam te spesifiseer waar sandbox kontroles geskryf sal word.\
Dit is ook moontlik om iets soortgelyks te doen deur `sandbox_vtrace_enable()` aan te roep en dan die logs fout van die buffer te verkry deur `sandbox_vtrace_report()` aan te roep.

### Sandbox Inspeksie

`libsandbox.dylib` voer 'n funksie genaamd sandbox\_inspect\_pid uit wat 'n lys van die sandbox toestand van 'n proses gee (insluitend uitbreidings). Maar, slegs platform binêre kan hierdie funksie gebruik.

### MacOS & iOS Sandbox Profiele

MacOS stoor stelselsandbox profiele in twee plekke: **/usr/share/sandbox/** en **/System/Library/Sandbox/Profiles**.

En as 'n derdeparty toepassing die _**com.apple.security.app-sandbox**_ regte het, pas die stelsel die **/System/Library/Sandbox/Profiles/application.sb** profiel op daardie proses toe.

In iOS, word die standaard profiel **container** genoem en ons het nie die SBPL teks voorstelling nie. In geheue, word hierdie sandbox voorgestel as 'n Toelaat/Weier binêre boom vir elke toestemming van die sandbox.

### Pasgemaakte SBPL in App Store toepassings

Dit kan moontlik wees vir maatskappye om hul toepassings te laat loop **met pasgemaakte Sandbox profiele** (in plaas van met die standaard een). Hulle moet die regte **`com.apple.security.temporary-exception.sbpl`** gebruik wat deur Apple goedgekeur moet word.

Dit is moontlik om die definisie van hierdie regte in **`/System/Library/Sandbox/Profiles/application.sb:`** te kontroleer.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
This will **eval die string na hierdie regte** as 'n Sandbox-profiel.

### Kompilering & dekompilering van 'n Sandbox-profiel

Die **`sandbox-exec`** hulpmiddel gebruik die funksies `sandbox_compile_*` van `libsandbox.dylib`. Die hooffunksies wat ge-exporteer word is: `sandbox_compile_file` (verwag 'n lêer pad, param `-f`), `sandbox_compile_string` (verwag 'n string, param `-p`), `sandbox_compile_name` (verwag 'n naam van 'n houer, param `-n`), `sandbox_compile_entitlements` (verwag regte plist).

Hierdie omgekeerde en [**oopbron weergawe van die hulpmiddel sandbox-exec**](https://newosxbook.com/src.jl?tree=listings\&file=/sandbox\_exec.c) laat toe dat **`sandbox-exec`** in 'n lêer die gecompileerde sandbox-profiel skryf.

Boonop, om 'n proses binne 'n houer te beperk, kan dit `sandbox_spawnattrs_set[container/profilename]` aanroep en 'n houer of voorafbestaande profiel deurgee.

## Foutopsporing & Omseiling van Sandbox

Op macOS, anders as iOS waar prosesse vanaf die begin deur die kern gesandboks is, **moet prosesse self in die sandbox opt-in**. Dit beteken op macOS, 'n proses is nie deur die sandbox beperk totdat dit aktief besluit om daarin te gaan, alhoewel App Store-apps altyd gesandboks is.

Prosesse word outomaties gesandboks vanaf gebruikersland wanneer hulle begin as hulle die regte het: `com.apple.security.app-sandbox`. Vir 'n gedetailleerde verduideliking van hierdie proses, kyk:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

## **Sandbox-uitbreidings**

Uitbreidings laat toe om verdere voorregte aan 'n objek te gee en word verkry deur een van die funksies aan te roep:

* `sandbox_issue_extension`
* `sandbox_extension_issue_file[_with_new_type]`
* `sandbox_extension_issue_mach`
* `sandbox_extension_issue_iokit_user_client_class`
* `sandbox_extension_issue_iokit_registry_rentry_class`
* `sandbox_extension_issue_generic`
* `sandbox_extension_issue_posix_ipc`

Die uitbreidings word in die tweede MACF etiketgleuf gestoor wat toeganklik is vanaf die proses kredensiale. Die volgende **`sbtool`** kan toegang tot hierdie inligting verkry.

Let daarop dat uitbreidings gewoonlik toegeken word deur toegelate prosesse, byvoorbeeld, `tccd` sal die uitbreidings-token van `com.apple.tcc.kTCCServicePhotos` toeken wanneer 'n proses probeer het om toegang tot die foto's te verkry en in 'n XPC-boodskap toegelaat is. Dan sal die proses die uitbreidings-token moet verbruik sodat dit daaraan bygevoeg word.\
Let daarop dat die uitbreidings-token lang heksadesimale is wat die toegekende toestemmings kodeer. Hulle het egter nie die toegelate PID hardgecodeer nie, wat beteken dat enige proses met toegang tot die token **deur verskeie prosesse verbruik kan word**.

Let daarop dat uitbreidings baie verwant is aan regte, so om sekere regte te hê, kan sekere uitbreidings outomaties toeken.

### **Kontroleer PID Voorregte**

[**Volgens hierdie**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), die **`sandbox_check`** funksies (dit is 'n `__mac_syscall`), kan **kontroleer of 'n operasie toegelaat word of nie** deur die sandbox in 'n sekere PID, oudit-token of unieke ID.

Die [**hulpmiddel sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) (vind dit [gecompileer hier](https://newosxbook.com/articles/hitsb.html)) kan kontroleer of 'n PID sekere aksies kan uitvoer:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Dit is ook moontlik om die sandbox te suspend en te unsuspend met die funksies `sandbox_suspend` en `sandbox_unsuspend` van `libsystem_sandbox.dylib`.

Let daarop dat om die suspend-funksie aan te roep, sommige regte nagegaan word om die oproeper te magtig om dit aan te roep soos:

* com.apple.private.security.sandbox-manager
* com.apple.security.print
* com.apple.security.temporary-exception.audio-unit-host

## mac\_syscall

Hierdie stelselaanroep (#381) verwag een string eerste argument wat die module sal aandui om te loop, en dan 'n kode in die tweede argument wat die funksie sal aandui om te loop. Dan sal die derde argument afhang van die funksie wat uitgevoer word.

Die funksie `___sandbox_ms` oproep verpak `mac_syscall` wat in die eerste argument `"Sandbox"` aandui net soos `___sandbox_msp` 'n wrapper van `mac_set_proc` (#387) is. Dan kan sommige van die ondersteunde kodes deur `___sandbox_ms` in hierdie tabel gevind word:

* **set\_profile (#0)**: Pas 'n gecompileerde of benoemde profiel op 'n proses toe.
* **platform\_policy (#1)**: Handhaaf platform-spesifieke beleidskontroles (verskil tussen macOS en iOS).
* **check\_sandbox (#2)**: Voer 'n handmatige kontrole van 'n spesifieke sandbox-operasie uit.
* **note (#3)**: Voeg 'n annotasie by 'n Sandbox
* **container (#4)**: Koppel 'n annotasie aan 'n sandbox, tipies vir debugging of identifikasie.
* **extension\_issue (#5)**: Genereer 'n nuwe uitbreiding vir 'n proses.
* **extension\_consume (#6)**: Verbruik 'n gegewe uitbreiding.
* **extension\_release (#7)**: Vry die geheue wat aan 'n verbruikte uitbreiding gekoppel is.
* **extension\_update\_file (#8)**: Wysig parameters van 'n bestaande lêer uitbreiding binne die sandbox.
* **extension\_twiddle (#9)**: Pas 'n bestaande lêer uitbreiding aan of wysig (bv. TextEdit, rtf, rtfd).
* **suspend (#10)**: Tydelik alle sandbox kontroles suspend (vereis toepaslike regte).
* **unsuspend (#11)**: Herbegin alle voorheen gesuspendeerde sandbox kontroles.
* **passthrough\_access (#12)**: Laat direkte passthrough toegang tot 'n hulpbron toe, wat sandbox kontroles omseil.
* **set\_container\_path (#13)**: (slegs iOS) Stel 'n houer pad vir 'n app-groep of onderteken ID in.
* **container\_map (#14)**: (slegs iOS) Verkry 'n houer pad van `containermanagerd`.
* **sandbox\_user\_state\_item\_buffer\_send (#15)**: (iOS 10+) Stel gebruikersmodus metadata in die sandbox.
* **inspect (#16)**: Verskaf debug-inligting oor 'n sandboxed proses.
* **dump (#18)**: (macOS 11) Dump die huidige profiel van 'n sandbox vir analise.
* **vtrace (#19)**: Volg sandbox operasies vir monitering of debugging.
* **builtin\_profile\_deactivate (#20)**: (macOS < 11) Deaktiveer benoemde profiele (bv. `pe_i_can_has_debugger`).
* **check\_bulk (#21)**: Voer verskeie `sandbox_check` operasies in 'n enkele oproep uit.
* **reference\_retain\_by\_audit\_token (#28)**: Skep 'n verwysing vir 'n oudit token vir gebruik in sandbox kontroles.
* **reference\_release (#29)**: Vry 'n voorheen behoue oudit token verwysing.
* **rootless\_allows\_task\_for\_pid (#30)**: Verifieer of `task_for_pid` toegelaat word (soortgelyk aan `csr` kontroles).
* **rootless\_whitelist\_push (#31)**: (macOS) Pas 'n Stelselintegriteitbeskerming (SIP) manifestlêer toe.
* **rootless\_whitelist\_check (preflight) (#32)**: Kontroleer die SIP manifestlêer voor uitvoering.
* **rootless\_protected\_volume (#33)**: (macOS) Pas SIP beskerming toe op 'n skyf of partisie.
* **rootless\_mkdir\_protected (#34)**: Pas SIP/DataVault beskerming toe op 'n gids skep proses.

## Sandbox.kext

Let daarop dat in iOS die kernuitbreiding **hardcoded al die profiele** binne die `__TEXT.__const` segment bevat om te verhoed dat hulle gewysig word. Die volgende is 'n paar interessante funksies van die kernuitbreiding:

* **`hook_policy_init`**: Dit haak `mpo_policy_init` en dit word genoem na `mac_policy_register`. Dit voer die meeste van die inisialisasies van die Sandbox uit. Dit inisialiseer ook SIP.
* **`hook_policy_initbsd`**: Dit stel die sysctl-koppelvlak op wat `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` en `security.mac.sandbox.debug_mode` registreer (as dit met `PE_i_can_has_debugger` geboot is).
* **`hook_policy_syscall`**: Dit word deur `mac_syscall` aangeroep met "Sandbox" as eerste argument en kode wat die operasie in die tweede aandui. 'n Skakel word gebruik om die kode te vind wat volgens die aangevraagde kode moet loop.

### MACF Hooks

**`Sandbox.kext`** gebruik meer as 'n honderd haakies via MACF. Meeste van die haakies sal net 'n paar triviale gevalle kontroleer wat die aksie toelaat as dit nie, sal hulle **`cred_sb_evalutate`** met die **akkrediteer** van MACF en 'n nommer wat ooreenstem met die **operasie** wat uitgevoer moet word en 'n **buffer** vir die uitvoer aanroep.

'n Goeie voorbeeld hiervan is die funksie **`_mpo_file_check_mmap`** wat **`mmap`** gehaak het en wat sal begin om te kontroleer of die nuwe geheue skryfbaar gaan wees (en as dit nie is nie, sal dit die uitvoering toelaat), dan sal dit kontroleer of dit vir die dyld gedeelde kas gebruik word en as dit so is, die uitvoering toelaat, en uiteindelik sal dit **`sb_evaluate_internal`** (of een van sy wrappers) aanroep om verdere toelaatbaarheid kontroles uit te voer.

Boonop, uit die honderd(s) haakies wat Sandbox gebruik, is daar 3 in die besonder wat baie interessant is:

* `mpo_proc_check_for`: Dit pas die profiel toe indien nodig en as dit nie voorheen toegepas is nie.
* `mpo_vnode_check_exec`: Geroep wanneer 'n proses die geassosieerde binêre laai, dan word 'n profielkontrole uitgevoer en ook 'n kontrole wat SUID/SGID uitvoerings verbied.
* `mpo_cred_label_update_execve`: Dit word aangeroep wanneer die etiket toegeken word. Dit is die langste een aangesien dit aangeroep word wanneer die binêre ten volle gelaai is, maar dit nog nie uitgevoer is nie. Dit sal aksies uitvoer soos om die sandbox objek te skep, die sandbox struktuur aan die kauth akkrediteer te heg, toegang tot mach-poorte te verwyder...

Let daarop dat **`_cred_sb_evalutate`** 'n wrapper oor **`sb_evaluate_internal`** is en hierdie funksie kry die akkrediteer wat oorgedra word en voer dan die evaluering uit met die **`eval`** funksie wat gewoonlik die **platform profiel** evalueer wat standaard op alle prosesse toegepas word en dan die **spesifieke proses profiel**. Let daarop dat die platform profiel een van die hoofkomponente van **SIP** in macOS is.

## Sandboxd

Sandbox het ook 'n gebruikersdemon wat die XPC Mach diens `com.apple.sandboxd` blootstel en die spesiale poort 14 (`HOST_SEATBELT_PORT`) bind wat die kernuitbreiding gebruik om met dit te kommunikeer. Dit blootstel 'n paar funksies met MIG.

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
