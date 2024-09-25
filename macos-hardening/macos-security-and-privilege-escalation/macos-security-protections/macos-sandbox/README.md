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

MacOS Sandbox (inizialmente chiamato Seatbelt) **limita le applicazioni** che vengono eseguite all'interno della sandbox alle **azioni consentite specificate nel profilo Sandbox** con cui l'app è in esecuzione. Questo aiuta a garantire che **l'applicazione accederà solo alle risorse previste**.

Qualsiasi app con l'**entitlement** **`com.apple.security.app-sandbox`** verrà eseguita all'interno della sandbox. **I binari Apple** vengono solitamente eseguiti all'interno di una Sandbox, e tutte le applicazioni dell'**App Store hanno quell'entitlement**. Quindi diverse applicazioni verranno eseguite all'interno della sandbox.

Per controllare cosa un processo può o non può fare, la **Sandbox ha hook** in quasi ogni operazione che un processo potrebbe tentare (inclusi la maggior parte delle syscalls) utilizzando **MACF**. Tuttavia, d**ipendendo** dagli **entitlements** dell'app, la Sandbox potrebbe essere più permissiva con il processo.

Alcuni componenti importanti della Sandbox sono:

* L'**estensione del kernel** `/System/Library/Extensions/Sandbox.kext`
* Il **framework privato** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Un **daemon** in esecuzione in userland `/usr/libexec/sandboxd`
* I **contenitori** `~/Library/Containers`

### Containers

Ogni applicazione sandboxed avrà il proprio contenitore in `~/Library/Containers/{CFBundleIdentifier}` :
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
All'interno di ogni cartella dell'ID bundle puoi trovare il **plist** e la **directory Data** dell'App con una struttura che imita la cartella Home:
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
Nota che anche se i symlink sono presenti per "uscire" dal Sandbox e accedere ad altre cartelle, l'App deve comunque **avere permessi** per accedervi. Questi permessi sono all'interno del **`.plist`** in `RedirectablePaths`.
{% endhint %}

Il **`SandboxProfileData`** è il profilo sandbox compilato CFData codificato in B64.
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
Tutto ciò che viene creato/modificato da un'applicazione in Sandbox riceverà l'**attributo di quarantena**. Questo impedirà a uno spazio sandbox di attivare Gatekeeper se l'app sandbox tenta di eseguire qualcosa con **`open`**.
{% endhint %}

## Profili Sandbox

I profili Sandbox sono file di configurazione che indicano cosa sarà **consentito/vietato** in quel **Sandbox**. Utilizza il **Sandbox Profile Language (SBPL)**, che utilizza il linguaggio di programmazione [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

Qui puoi trovare un esempio:
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
Controlla questa [**ricerca**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **per verificare ulteriori azioni che potrebbero essere consentite o negate.**

Nota che nella versione compilata di un profilo, i nomi delle operazioni sono sostituiti dalle loro voci in un array conosciuto dalla dylib e dal kext, rendendo la versione compilata più corta e più difficile da leggere.
{% endhint %}

I **servizi di sistema** importanti vengono eseguiti anche all'interno del proprio **sandbox** personalizzato, come il servizio `mdnsresponder`. Puoi visualizzare questi **profili sandbox** personalizzati all'interno di:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**
* Altri profili sandbox possono essere controllati su [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Le app dell'**App Store** utilizzano il **profilo** **`/System/Library/Sandbox/Profiles/application.sb`**. Puoi controllare in questo profilo come i diritti, come **`com.apple.security.network.server`**, consentono a un processo di utilizzare la rete.

SIP è un profilo Sandbox chiamato platform\_profile in /System/Library/Sandbox/rootless.conf

### Esempi di profili Sandbox

Per avviare un'applicazione con un **profilo sandbox specifico** puoi usare:
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
Nota che il **software** **scritto da Apple** che gira su **Windows** **non ha precauzioni di sicurezza aggiuntive**, come il sandboxing delle applicazioni.
{% endhint %}

Esempi di bypass:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (sono in grado di scrivere file al di fuori del sandbox il cui nome inizia con `~$`).

### Tracciamento del Sandbox

#### Via profilo

È possibile tracciare tutti i controlli che il sandbox esegue ogni volta che un'azione viene verificata. Per farlo, crea semplicemente il seguente profilo:

{% code title="trace.sb" %}
```scheme
(version 1)
(trace /tmp/trace.out)
```
{% endcode %}

E poi esegui semplicemente qualcosa utilizzando quel profilo:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
In `/tmp/trace.out` potrai vedere ogni controllo della sandbox eseguito ogni volta che è stato chiamato (quindi, molti duplicati).

È anche possibile tracciare la sandbox utilizzando il parametro **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

La funzione `sandbox_set_trace_path` esportata da `libsystem_sandbox.dylib` consente di specificare un nome file di traccia in cui verranno scritti i controlli della sandbox.\
È anche possibile fare qualcosa di simile chiamando `sandbox_vtrace_enable()` e poi ottenendo i log di errore dal buffer chiamando `sandbox_vtrace_report()`.

### Ispezione della Sandbox

`libsandbox.dylib` esporta una funzione chiamata sandbox\_inspect\_pid che fornisce un elenco dello stato della sandbox di un processo (inclusi le estensioni). Tuttavia, solo i binari della piattaforma possono utilizzare questa funzione.

### Profili Sandbox di MacOS e iOS

MacOS memorizza i profili della sandbox di sistema in due posizioni: **/usr/share/sandbox/** e **/System/Library/Sandbox/Profiles**.

E se un'applicazione di terze parti porta il diritto _**com.apple.security.app-sandbox**_, il sistema applica il profilo **/System/Library/Sandbox/Profiles/application.sb** a quel processo.

In iOS, il profilo predefinito si chiama **container** e non abbiamo la rappresentazione testuale SBPL. In memoria, questa sandbox è rappresentata come un albero binario di Permesso/Nego per ciascuna autorizzazione della sandbox.

### SBPL personalizzato nelle app dell'App Store

Potrebbe essere possibile per le aziende far funzionare le loro app **con profili Sandbox personalizzati** (invece di quello predefinito). Devono utilizzare il diritto **`com.apple.security.temporary-exception.sbpl`** che deve essere autorizzato da Apple.

È possibile controllare la definizione di questo diritto in **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Questo **valuterà la stringa dopo questo diritto** come un profilo Sandbox.

### Compilazione e decompilazione di un profilo Sandbox

Lo strumento **`sandbox-exec`** utilizza le funzioni `sandbox_compile_*` da `libsandbox.dylib`. Le principali funzioni esportate sono: `sandbox_compile_file` (si aspetta un percorso di file, parametro `-f`), `sandbox_compile_string` (si aspetta una stringa, parametro `-p`), `sandbox_compile_name` (si aspetta un nome di un contenitore, parametro `-n`), `sandbox_compile_entitlements` (si aspetta un plist di diritti).

Questa versione invertita e [**open source dello strumento sandbox-exec**](https://newosxbook.com/src.jl?tree=listings\&file=/sandbox\_exec.c) consente di far scrivere a **`sandbox-exec`** in un file il profilo sandbox compilato.

Inoltre, per confinare un processo all'interno di un contenitore, potrebbe chiamare `sandbox_spawnattrs_set[container/profilename]` e passare un contenitore o un profilo preesistente.

## Debug e Bypass Sandbox

Su macOS, a differenza di iOS dove i processi sono sandboxati fin dall'inizio dal kernel, **i processi devono optare per la sandbox da soli**. Questo significa che su macOS, un processo non è limitato dalla sandbox fino a quando non decide attivamente di entrarci, anche se le app dell'App Store sono sempre sandboxate.

I processi sono automaticamente sandboxati dal userland quando iniziano se hanno il diritto: `com.apple.security.app-sandbox`. Per una spiegazione dettagliata di questo processo controlla:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

## **Estensioni Sandbox**

Le estensioni consentono di dare ulteriori privilegi a un oggetto e vengono attivate chiamando una delle funzioni:

* `sandbox_issue_extension`
* `sandbox_extension_issue_file[_with_new_type]`
* `sandbox_extension_issue_mach`
* `sandbox_extension_issue_iokit_user_client_class`
* `sandbox_extension_issue_iokit_registry_rentry_class`
* `sandbox_extension_issue_generic`
* `sandbox_extension_issue_posix_ipc`

Le estensioni sono memorizzate nel secondo slot di etichetta MACF accessibile dalle credenziali del processo. Il seguente **`sbtool`** può accedere a queste informazioni.

Nota che le estensioni sono solitamente concesse dai processi autorizzati, ad esempio, `tccd` concederà il token di estensione di `com.apple.tcc.kTCCServicePhotos` quando un processo tenta di accedere alle foto ed è stato autorizzato in un messaggio XPC. Poi, il processo dovrà consumare il token di estensione affinché venga aggiunto a esso.\
Nota che i token di estensione sono lunghi esadecimali che codificano i permessi concessi. Tuttavia, non hanno il PID autorizzato hardcoded, il che significa che qualsiasi processo con accesso al token potrebbe essere **consumato da più processi**.

Nota che le estensioni sono molto correlate ai diritti, quindi avere determinati diritti potrebbe automaticamente concedere determinate estensioni.

### **Controlla i privilegi PID**

[**Secondo questo**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), le funzioni **`sandbox_check`** (è un `__mac_syscall`), possono controllare **se un'operazione è consentita o meno** dalla sandbox in un certo PID, audit token o ID unico.

Il [**tool sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) (trovalo [compilato qui](https://newosxbook.com/articles/hitsb.html)) può controllare se un PID può eseguire determinate azioni:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

È anche possibile sospendere e riattivare il sandbox utilizzando le funzioni `sandbox_suspend` e `sandbox_unsuspend` da `libsystem_sandbox.dylib`.

Nota che per chiamare la funzione di sospensione vengono controllati alcuni diritti per autorizzare il chiamante a chiamarla come:

* com.apple.private.security.sandbox-manager
* com.apple.security.print
* com.apple.security.temporary-exception.audio-unit-host

## mac\_syscall

Questa chiamata di sistema (#381) si aspetta un primo argomento stringa che indicherà il modulo da eseguire, e poi un codice nel secondo argomento che indicherà la funzione da eseguire. Poi il terzo argomento dipenderà dalla funzione eseguita.

La funzione `___sandbox_ms` chiama `mac_syscall` indicando nel primo argomento `"Sandbox"` proprio come `___sandbox_msp` è un wrapper di `mac_set_proc` (#387). Poi, alcuni dei codici supportati da `___sandbox_ms` possono essere trovati in questa tabella:

* **set\_profile (#0)**: Applica un profilo compilato o nominato a un processo.
* **platform\_policy (#1)**: Applica controlli di policy specifici per la piattaforma (varia tra macOS e iOS).
* **check\_sandbox (#2)**: Esegue un controllo manuale di un'operazione sandbox specifica.
* **note (#3)**: Aggiunge una notazione a un Sandbox
* **container (#4)**: Attacca un'annotazione a un sandbox, tipicamente per il debug o identificazione.
* **extension\_issue (#5)**: Genera una nuova estensione per un processo.
* **extension\_consume (#6)**: Consuma un'estensione data.
* **extension\_release (#7)**: Rilascia la memoria legata a un'estensione consumata.
* **extension\_update\_file (#8)**: Modifica i parametri di un'estensione di file esistente all'interno del sandbox.
* **extension\_twiddle (#9)**: Regola o modifica un'estensione di file esistente (es. TextEdit, rtf, rtfd).
* **suspend (#10)**: Sospende temporaneamente tutti i controlli del sandbox (richiede diritti appropriati).
* **unsuspend (#11)**: Riprende tutti i controlli del sandbox precedentemente sospesi.
* **passthrough\_access (#12)**: Consente l'accesso diretto a una risorsa, bypassando i controlli del sandbox.
* **set\_container\_path (#13)**: (solo iOS) Imposta un percorso del contenitore per un gruppo di app o ID di firma.
* **container\_map (#14)**: (solo iOS) Recupera un percorso del contenitore da `containermanagerd`.
* **sandbox\_user\_state\_item\_buffer\_send (#15)**: (iOS 10+) Imposta i metadati in modalità utente nel sandbox.
* **inspect (#16)**: Fornisce informazioni di debug su un processo sandboxed.
* **dump (#18)**: (macOS 11) Dump del profilo attuale di un sandbox per analisi.
* **vtrace (#19)**: Traccia le operazioni del sandbox per monitoraggio o debug.
* **builtin\_profile\_deactivate (#20)**: (macOS < 11) Disattiva profili nominati (es. `pe_i_can_has_debugger`).
* **check\_bulk (#21)**: Esegue più operazioni `sandbox_check` in una singola chiamata.
* **reference\_retain\_by\_audit\_token (#28)**: Crea un riferimento per un token di audit da utilizzare nei controlli del sandbox.
* **reference\_release (#29)**: Rilascia un riferimento a un token di audit precedentemente mantenuto.
* **rootless\_allows\_task\_for\_pid (#30)**: Verifica se `task_for_pid` è consentito (simile ai controlli `csr`).
* **rootless\_whitelist\_push (#31)**: (macOS) Applica un file di manifest di System Integrity Protection (SIP).
* **rootless\_whitelist\_check (preflight) (#32)**: Controlla il file di manifest SIP prima dell'esecuzione.
* **rootless\_protected\_volume (#33)**: (macOS) Applica protezioni SIP a un disco o partizione.
* **rootless\_mkdir\_protected (#34)**: Applica protezione SIP/DataVault a un processo di creazione di directory.

## Sandbox.kext

Nota che in iOS l'estensione del kernel contiene **tutti i profili hardcoded** all'interno del segmento `__TEXT.__const` per evitare che vengano modificati. Le seguenti sono alcune funzioni interessanti dall'estensione del kernel:

* **`hook_policy_init`**: Collega `mpo_policy_init` ed è chiamato dopo `mac_policy_register`. Esegue la maggior parte delle inizializzazioni del Sandbox. Inizializza anche SIP.
* **`hook_policy_initbsd`**: Imposta l'interfaccia sysctl registrando `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` e `security.mac.sandbox.debug_mode` (se avviato con `PE_i_can_has_debugger`).
* **`hook_policy_syscall`**: È chiamato da `mac_syscall` con "Sandbox" come primo argomento e codice che indica l'operazione nel secondo. Viene utilizzato uno switch per trovare il codice da eseguire in base al codice richiesto.

### MACF Hooks

**`Sandbox.kext`** utilizza più di un centinaio di hook tramite MACF. La maggior parte degli hook controllerà solo alcuni casi banali che consentono di eseguire l'azione, altrimenti chiameranno **`cred_sb_evalutate`** con le **credenziali** da MACF e un numero corrispondente all'**operazione** da eseguire e un **buffer** per l'output.

Un buon esempio di ciò è la funzione **`_mpo_file_check_mmap`** che ha agganciato **`mmap`** e che inizierà a controllare se la nuova memoria sarà scrivibile (e se non lo è, consentirà l'esecuzione), poi controllerà se è utilizzata per la cache condivisa dyld e, in tal caso, consentirà l'esecuzione, e infine chiamerà **`sb_evaluate_internal`** (o uno dei suoi wrapper) per eseguire ulteriori controlli di autorizzazione.

Inoltre, tra i centinaia di hook utilizzati dal Sandbox, ce ne sono 3 in particolare che sono molto interessanti:

* `mpo_proc_check_for`: Applica il profilo se necessario e se non era stato precedentemente applicato.
* `mpo_vnode_check_exec`: Chiamato quando un processo carica il binario associato, quindi viene eseguito un controllo del profilo e anche un controllo che vieta le esecuzioni SUID/SGID.
* `mpo_cred_label_update_execve`: Questo viene chiamato quando l'etichetta viene assegnata. Questo è il più lungo poiché viene chiamato quando il binario è completamente caricato ma non è ancora stato eseguito. Eseguirà azioni come la creazione dell'oggetto sandbox, l'attacco della struttura sandbox alle credenziali kauth, la rimozione dell'accesso alle porte mach...

Nota che **`_cred_sb_evalutate`** è un wrapper su **`sb_evaluate_internal`** e questa funzione ottiene le credenziali passate e poi esegue la valutazione utilizzando la funzione **`eval`** che di solito valuta il **profilo della piattaforma** che è per impostazione predefinita applicato a tutti i processi e poi il **profilo del processo specifico**. Nota che il profilo della piattaforma è uno dei componenti principali di **SIP** in macOS.

## Sandboxd

Il Sandbox ha anche un demone utente in esecuzione che espone il servizio XPC Mach `com.apple.sandboxd` e lega la porta speciale 14 (`HOST_SEATBELT_PORT`) che l'estensione del kernel utilizza per comunicare con esso. Espone alcune funzioni utilizzando MIG.

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
