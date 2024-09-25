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

## Grundinformationen

MacOS Sandbox (anfänglich Seatbelt genannt) **beschränkt Anwendungen**, die innerhalb des Sandboxes ausgeführt werden, auf die **erlaubten Aktionen, die im Sandbox-Profil** festgelegt sind, mit dem die App ausgeführt wird. Dies hilft sicherzustellen, dass **die Anwendung nur auf erwartete Ressourcen zugreift**.

Jede App mit der **Berechtigung** **`com.apple.security.app-sandbox`** wird innerhalb des Sandboxes ausgeführt. **Apple-Binärdateien** werden normalerweise innerhalb eines Sandboxes ausgeführt, und alle Anwendungen aus dem **App Store haben diese Berechtigung**. Daher werden mehrere Anwendungen innerhalb des Sandboxes ausgeführt.

Um zu kontrollieren, was ein Prozess tun oder nicht tun kann, hat der **Sandbox Hooks** in fast jede Operation, die ein Prozess versuchen könnte (einschließlich der meisten Syscalls), unter Verwendung von **MACF**. Allerdings kann der **Sandbox je nach** den **Berechtigungen** der App permissiver mit dem Prozess umgehen.

Einige wichtige Komponenten des Sandboxes sind:

* Die **Kernel-Erweiterung** `/System/Library/Extensions/Sandbox.kext`
* Das **private Framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Ein **Daemon**, der im Userland läuft `/usr/libexec/sandboxd`
* Die **Container** `~/Library/Containers`

### Container

Jede sandboxed Anwendung hat ihren eigenen Container in `~/Library/Containers/{CFBundleIdentifier}` :
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
Innerhalb jedes Bundle-ID-Ordners finden Sie die **plist** und das **Datenverzeichnis** der App mit einer Struktur, die dem Home-Ordner ähnelt:
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
Beachten Sie, dass selbst wenn die Symlinks vorhanden sind, um aus dem Sandbox zu "entkommen" und auf andere Ordner zuzugreifen, die App dennoch **Berechtigungen haben muss**, um auf sie zuzugreifen. Diese Berechtigungen befinden sich in der **`.plist`** in den `RedirectablePaths`.
{% endhint %}

Die **`SandboxProfileData`** ist das kompilierte Sandbox-Profil CFData, das in B64 kodiert ist.
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
Alles, was von einer Sandbox-Anwendung erstellt oder geändert wird, erhält das **Quarantäneattribut**. Dies verhindert einen Sandbox-Raum, indem Gatekeeper ausgelöst wird, wenn die Sandbox-App versucht, etwas mit **`open`** auszuführen.
{% endhint %}

## Sandbox-Profile

Die Sandbox-Profile sind Konfigurationsdateien, die angeben, was in dieser **Sandbox** **erlaubt/verboten** ist. Es verwendet die **Sandbox Profile Language (SBPL)**, die die [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) Programmiersprache nutzt.

Hier finden Sie ein Beispiel:
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
Überprüfen Sie diese [**Forschung**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **um weitere Aktionen zu überprüfen, die erlaubt oder verweigert werden könnten.**

Beachten Sie, dass in der kompilierten Version eines Profils die Namen der Operationen durch ihre Einträge in einem Array ersetzt werden, das von der dylib und dem kext bekannt ist, wodurch die kompilierte Version kürzer und schwerer lesbar wird.
{% endhint %}

Wichtige **Systemdienste** laufen ebenfalls in ihrem eigenen benutzerdefinierten **Sandbox**, wie der Dienst `mdnsresponder`. Sie können diese benutzerdefinierten **Sandbox-Profile** einsehen unter:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**
* Andere Sandbox-Profile können unter [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) überprüft werden.

**App Store**-Apps verwenden das **Profil** **`/System/Library/Sandbox/Profiles/application.sb`**. Sie können in diesem Profil überprüfen, wie Berechtigungen wie **`com.apple.security.network.server`** einem Prozess erlauben, das Netzwerk zu nutzen.

SIP ist ein Sandbox-Profil, das in /System/Library/Sandbox/rootless.conf als platform\_profile bezeichnet wird.

### Beispiele für Sandbox-Profile

Um eine Anwendung mit einem **spezifischen Sandbox-Profil** zu starten, können Sie verwenden:
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
Beachten Sie, dass die **von Apple verfasste** **Software**, die auf **Windows** läuft, **keine zusätzlichen Sicherheitsvorkehrungen** hat, wie z.B. die Anwendungssandbox.
{% endhint %}

Beispiele für Umgehungen:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (sie können Dateien außerhalb der Sandbox schreiben, deren Name mit `~$` beginnt).

### Sandbox-Überwachung

#### Über Profil

Es ist möglich, alle Überprüfungen zu verfolgen, die die Sandbox jedes Mal durchführt, wenn eine Aktion überprüft wird. Erstellen Sie dazu einfach das folgende Profil:

{% code title="trace.sb" %}
```scheme
(version 1)
(trace /tmp/trace.out)
```
{% endcode %}

Und dann einfach etwas mit diesem Profil ausführen:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
In `/tmp/trace.out` können Sie jede Sandbox-Prüfung sehen, die jedes Mal durchgeführt wurde, wenn sie aufgerufen wurde (also viele Duplikate).

Es ist auch möglich, die Sandbox mit dem **`-t`** Parameter zu verfolgen: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Über die API

Die Funktion `sandbox_set_trace_path`, die von `libsystem_sandbox.dylib` exportiert wird, ermöglicht es, einen Trace-Dateinamen anzugeben, in den Sandbox-Prüfungen geschrieben werden.\
Es ist auch möglich, etwas Ähnliches zu tun, indem man `sandbox_vtrace_enable()` aufruft und dann die Protokollfehler aus dem Puffer mit `sandbox_vtrace_report()` abruft.

### Sandbox-Inspektion

`libsandbox.dylib` exportiert eine Funktion namens sandbox\_inspect\_pid, die eine Liste des Sandbox-Zustands eines Prozesses (einschließlich Erweiterungen) liefert. Allerdings können nur Plattform-Binärdateien diese Funktion verwenden.

### MacOS & iOS Sandbox-Profile

MacOS speichert System-Sandbox-Profile an zwei Orten: **/usr/share/sandbox/** und **/System/Library/Sandbox/Profiles**.

Und wenn eine Drittanbieteranwendung das _**com.apple.security.app-sandbox**_ Recht hat, wendet das System das **/System/Library/Sandbox/Profiles/application.sb** Profil auf diesen Prozess an.

In iOS wird das Standardprofil **container** genannt und wir haben keine SBPL-Textdarstellung. Im Speicher wird diese Sandbox als Erlauben/Verweigern-Binärbaum für jede Berechtigung aus der Sandbox dargestellt.

### Benutzerdefinierte SBPL in App Store-Apps

Es könnte für Unternehmen möglich sein, ihre Apps **mit benutzerdefinierten Sandbox-Profilen** (anstatt mit dem Standardprofil) auszuführen. Sie müssen das Recht **`com.apple.security.temporary-exception.sbpl`** verwenden, das von Apple genehmigt werden muss.

Es ist möglich, die Definition dieses Rechts in **`/System/Library/Sandbox/Profiles/application.sb:`** zu überprüfen.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Dies wird **den String nach diesem Recht** als ein Sandbox-Profil **eval**.

### Kompilieren & Dekompilieren eines Sandbox-Profils

Das **`sandbox-exec`**-Tool verwendet die Funktionen `sandbox_compile_*` aus `libsandbox.dylib`. Die Hauptfunktionen, die exportiert werden, sind: `sandbox_compile_file` (erwartet einen Dateipfad, Parameter `-f`), `sandbox_compile_string` (erwartet einen String, Parameter `-p`), `sandbox_compile_name` (erwartet einen Namen eines Containers, Parameter `-n`), `sandbox_compile_entitlements` (erwartet Entitlements plist).

Diese umgekehrte und [**Open-Source-Version des Tools sandbox-exec**](https://newosxbook.com/src.jl?tree=listings\&file=/sandbox\_exec.c) ermöglicht es, dass **`sandbox-exec`** in eine Datei das kompilierte Sandbox-Profil schreibt.

Darüber hinaus kann es, um einen Prozess innerhalb eines Containers einzuschränken, `sandbox_spawnattrs_set[container/profilename]` aufrufen und einen Container oder ein bereits vorhandenes Profil übergeben.

## Debuggen & Umgehen der Sandbox

Auf macOS, im Gegensatz zu iOS, wo Prozesse von Anfang an durch den Kernel sandboxed sind, **müssen Prozesse selbst in die Sandbox eintreten**. Das bedeutet, dass ein Prozess auf macOS nicht durch die Sandbox eingeschränkt ist, bis er aktiv entscheidet, sie zu betreten, obwohl Apps aus dem App Store immer sandboxed sind.

Prozesse werden automatisch aus dem Userland sandboxed, wenn sie starten, wenn sie das Recht haben: `com.apple.security.app-sandbox`. Für eine detaillierte Erklärung dieses Prozesses siehe:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

## **Sandbox-Erweiterungen**

Erweiterungen ermöglichen es, einem Objekt weitere Berechtigungen zu geben, und werden durch den Aufruf einer der Funktionen vergeben:

* `sandbox_issue_extension`
* `sandbox_extension_issue_file[_with_new_type]`
* `sandbox_extension_issue_mach`
* `sandbox_extension_issue_iokit_user_client_class`
* `sandbox_extension_issue_iokit_registry_rentry_class`
* `sandbox_extension_issue_generic`
* `sandbox_extension_issue_posix_ipc`

Die Erweiterungen werden im zweiten MACF-Label-Slot gespeichert, der von den Prozessanmeldeinformationen zugänglich ist. Das folgende **`sbtool`** kann auf diese Informationen zugreifen.

Beachten Sie, dass Erweiterungen normalerweise von erlaubten Prozessen gewährt werden, zum Beispiel wird `tccd` das Erweiterungstoken von `com.apple.tcc.kTCCServicePhotos` gewähren, wenn ein Prozess versucht hat, auf die Fotos zuzugreifen und in einer XPC-Nachricht erlaubt wurde. Dann muss der Prozess das Erweiterungstoken konsumieren, damit es hinzugefügt wird.\
Beachten Sie, dass die Erweiterungstoken lange Hexadezimalzahlen sind, die die gewährten Berechtigungen kodieren. Sie haben jedoch die erlaubte PID nicht fest codiert, was bedeutet, dass jeder Prozess mit Zugriff auf das Token **von mehreren Prozessen konsumiert werden kann**.

Beachten Sie, dass Erweiterungen auch sehr mit Rechten verbunden sind, sodass das Vorhandensein bestimmter Rechte automatisch bestimmte Erweiterungen gewähren kann.

### **Überprüfen der PID-Berechtigungen**

[**Laut diesem**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s) können die **`sandbox_check`**-Funktionen (es ist ein `__mac_syscall`) überprüfen, **ob eine Operation erlaubt ist oder nicht** durch die Sandbox in einer bestimmten PID, Audit-Token oder eindeutige ID.

Das [**Tool sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) (finden Sie es [hier kompiliert](https://newosxbook.com/articles/hitsb.html)) kann überprüfen, ob eine PID bestimmte Aktionen ausführen kann:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Es ist auch möglich, den Sandbox zu suspendieren und wieder zu aktivieren, indem die Funktionen `sandbox_suspend` und `sandbox_unsuspend` aus `libsystem_sandbox.dylib` verwendet werden.

Beachten Sie, dass zur Aufruf der Suspend-Funktion einige Berechtigungen überprüft werden, um den Aufrufer zu autorisieren, sie aufzurufen, wie:

* com.apple.private.security.sandbox-manager
* com.apple.security.print
* com.apple.security.temporary-exception.audio-unit-host

## mac\_syscall

Dieser Systemaufruf (#381) erwartet ein String-Argument als ersten Parameter, das das Modul angibt, das ausgeführt werden soll, und dann einen Code im zweiten Argument, der die auszuführende Funktion angibt. Der dritte Parameter hängt dann von der ausgeführten Funktion ab.

Der Funktionsaufruf `___sandbox_ms` umschließt `mac_syscall`, wobei im ersten Argument `"Sandbox"` angegeben wird, genau wie `___sandbox_msp` ein Wrapper von `mac_set_proc` (#387) ist. Einige der unterstützten Codes von `___sandbox_ms` finden sich in dieser Tabelle:

* **set\_profile (#0)**: Wendet ein kompiliertes oder benanntes Profil auf einen Prozess an.
* **platform\_policy (#1)**: Erzwingt plattformspezifische Richtlinienprüfungen (variiert zwischen macOS und iOS).
* **check\_sandbox (#2)**: Führt eine manuelle Überprüfung einer bestimmten Sandbox-Operation durch.
* **note (#3)**: Fügt eine Annotation zu einer Sandbox hinzu.
* **container (#4)**: Fügt einer Sandbox eine Annotation hinzu, typischerweise zur Fehlersuche oder Identifikation.
* **extension\_issue (#5)**: Generiert eine neue Erweiterung für einen Prozess.
* **extension\_consume (#6)**: Verbraucht eine gegebene Erweiterung.
* **extension\_release (#7)**: Gibt den Speicher frei, der an eine verbrauchte Erweiterung gebunden ist.
* **extension\_update\_file (#8)**: Ändert Parameter einer bestehenden Dateierweiterung innerhalb der Sandbox.
* **extension\_twiddle (#9)**: Passt eine bestehende Dateierweiterung an oder ändert sie (z.B. TextEdit, rtf, rtfd).
* **suspend (#10)**: Unterbricht vorübergehend alle Sandbox-Prüfungen (erfordert entsprechende Berechtigungen).
* **unsuspend (#11)**: Setzt alle zuvor suspendierten Sandbox-Prüfungen fort.
* **passthrough\_access (#12)**: Erlaubt direkten Passthrough-Zugriff auf eine Ressource, umgeht Sandbox-Prüfungen.
* **set\_container\_path (#13)**: (nur iOS) Setzt einen Containerpfad für eine App-Gruppe oder eine Signatur-ID.
* **container\_map (#14)**: (nur iOS) Ruft einen Containerpfad von `containermanagerd` ab.
* **sandbox\_user\_state\_item\_buffer\_send (#15)**: (iOS 10+) Setzt Benutzermetadaten im Sandbox.
* **inspect (#16)**: Bietet Debug-Informationen über einen sandboxed Prozess.
* **dump (#18)**: (macOS 11) Dumpt das aktuelle Profil einer Sandbox zur Analyse.
* **vtrace (#19)**: Verfolgt Sandbox-Operationen zur Überwachung oder Fehlersuche.
* **builtin\_profile\_deactivate (#20)**: (macOS < 11) Deaktiviert benannte Profile (z.B. `pe_i_can_has_debugger`).
* **check\_bulk (#21)**: Führt mehrere `sandbox_check`-Operationen in einem einzigen Aufruf durch.
* **reference\_retain\_by\_audit\_token (#28)**: Erstellt eine Referenz für ein Audit-Token zur Verwendung in Sandbox-Prüfungen.
* **reference\_release (#29)**: Gibt eine zuvor gehaltene Audit-Token-Referenz frei.
* **rootless\_allows\_task\_for\_pid (#30)**: Überprüft, ob `task_for_pid` erlaubt ist (ähnlich wie `csr`-Prüfungen).
* **rootless\_whitelist\_push (#31)**: (macOS) Wendet eine Systemintegritätsschutz (SIP) Manifestdatei an.
* **rootless\_whitelist\_check (preflight) (#32)**: Überprüft die SIP-Manifestdatei vor der Ausführung.
* **rootless\_protected\_volume (#33)**: (macOS) Wendet SIP-Schutz auf eine Festplatte oder Partition an.
* **rootless\_mkdir\_protected (#34)**: Wendet SIP/DataVault-Schutz auf einen Verzeichnis-Erstellungsprozess an.

## Sandbox.kext

Beachten Sie, dass die Kernel-Erweiterung in iOS **alle Profile hardcodiert** im `__TEXT.__const`-Segment enthält, um zu verhindern, dass sie modifiziert werden. Folgendes sind einige interessante Funktionen aus der Kernel-Erweiterung:

* **`hook_policy_init`**: Es hookt `mpo_policy_init` und wird nach `mac_policy_register` aufgerufen. Es führt die meisten Initialisierungen der Sandbox durch. Es initialisiert auch SIP.
* **`hook_policy_initbsd`**: Es richtet die sysctl-Schnittstelle ein und registriert `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` und `security.mac.sandbox.debug_mode` (wenn mit `PE_i_can_has_debugger` gebootet).
* **`hook_policy_syscall`**: Es wird von `mac_syscall` mit "Sandbox" als erstem Argument und einem Code, der die Operation im zweiten angibt, aufgerufen. Ein Switch wird verwendet, um den auszuführenden Code entsprechend dem angeforderten Code zu finden.

### MACF Hooks

**`Sandbox.kext`** verwendet mehr als hundert Hooks über MACF. Die meisten Hooks überprüfen nur einige triviale Fälle, die es erlauben, die Aktion auszuführen; andernfalls rufen sie **`cred_sb_evalutate`** mit den **Anmeldeinformationen** von MACF und einer Nummer, die der **Operation** entspricht, die ausgeführt werden soll, sowie einem **Puffer** für die Ausgabe auf.

Ein gutes Beispiel dafür ist die Funktion **`_mpo_file_check_mmap`**, die **`mmap`** hookt und die überprüft, ob der neue Speicher beschreibbar sein wird (und wenn nicht, die Ausführung erlaubt), dann wird überprüft, ob er für den dyld Shared Cache verwendet wird, und falls ja, wird die Ausführung erlaubt, und schließlich wird **`sb_evaluate_internal`** (oder einer seiner Wrapper) aufgerufen, um weitere Erlaubnisprüfungen durchzuführen.

Darüber hinaus gibt es unter den Hunderten von Hooks, die die Sandbox verwendet, 3, die besonders interessant sind:

* `mpo_proc_check_for`: Es wendet das Profil an, wenn nötig, und wenn es zuvor nicht angewendet wurde.
* `mpo_vnode_check_exec`: Wird aufgerufen, wenn ein Prozess die zugehörige Binärdatei lädt, dann wird eine Profilüberprüfung durchgeführt und auch eine Überprüfung, die SUID/SGID-Ausführungen verbietet.
* `mpo_cred_label_update_execve`: Dies wird aufgerufen, wenn das Label zugewiesen wird. Dies ist der längste, da es aufgerufen wird, wenn die Binärdatei vollständig geladen ist, aber noch nicht ausgeführt wurde. Es führt Aktionen wie das Erstellen des Sandbox-Objekts, das Anhängen der Sandbox-Struktur an die kauth-Anmeldeinformationen und das Entfernen des Zugriffs auf Mach-Ports durch...

Beachten Sie, dass **`_cred_sb_evalutate`** ein Wrapper über **`sb_evaluate_internal`** ist und diese Funktion die übergebenen Anmeldeinformationen erhält und dann die Bewertung unter Verwendung der **`eval`**-Funktion durchführt, die normalerweise das **Plattformprofil** bewertet, das standardmäßig auf alle Prozesse angewendet wird, und dann das **spezifische Prozessprofil**. Beachten Sie, dass das Plattformprofil eines der Hauptkomponenten von **SIP** in macOS ist.

## Sandboxd

Die Sandbox hat auch einen Benutzerdämon, der den XPC Mach-Dienst `com.apple.sandboxd` bereitstellt und den speziellen Port 14 (`HOST_SEATBELT_PORT`) bindet, den die Kernel-Erweiterung zur Kommunikation mit ihm verwendet. Es stellt einige Funktionen über MIG bereit.

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
