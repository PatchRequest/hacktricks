# PsExec/Winexec/ScExec

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) para construir y **automatizar flujos de trabajo** fácilmente, impulsados por las herramientas comunitarias **más avanzadas** del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## ¿Cómo funcionan?

El proceso se describe en los pasos a continuación, ilustrando cómo se manipulan los binarios de servicio para lograr la ejecución remota en una máquina objetivo a través de SMB:

1. **Se copia un binario de servicio al recurso compartido ADMIN$ a través de SMB**.
2. **Se crea un servicio en la máquina remota** apuntando al binario.
3. El servicio se **inicia de forma remota**.
4. Al salir, el servicio se **detiene y se elimina el binario**.

### **Proceso de Ejecución Manual de PsExec**

Suponiendo que hay una carga útil ejecutable (creada con msfvenom y ofuscada usando Veil para evadir la detección de antivirus), llamada 'met8888.exe', que representa una carga útil de meterpreter reverse_http, se llevan a cabo los siguientes pasos:

- **Copiando el binario**: El ejecutable se copia al recurso compartido ADMIN$ desde un símbolo del sistema, aunque puede colocarse en cualquier parte del sistema de archivos para permanecer oculto.

- **Creando un servicio**: Utilizando el comando `sc` de Windows, que permite consultar, crear y eliminar servicios de Windows de forma remota, se crea un servicio llamado "meterpreter" que apunta al binario subido.

- **Iniciando el servicio**: El paso final implica iniciar el servicio, lo que probablemente resultará en un error de "tiempo de espera" debido a que el binario no es un binario de servicio genuino y no devuelve el código de respuesta esperado. Este error es irrelevante ya que el objetivo principal es la ejecución del binario.

La observación del listener de Metasploit revelará que la sesión se ha iniciado con éxito.

[Aprende más sobre el comando `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Encuentra pasos más detallados en: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**También podrías usar el binario PsExec.exe de Windows Sysinternals:**

![](<../../.gitbook/assets/image (165).png>)

También podrías usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) para construir y **automatizar flujos de trabajo** fácilmente, impulsados por las **herramientas comunitarias más avanzadas** del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
