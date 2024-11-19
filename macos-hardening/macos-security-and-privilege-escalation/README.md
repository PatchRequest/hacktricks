# Seguridad de macOS y Escalación de Privilegios

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Únete al [**Discord de HackenProof**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de bugs.

**Perspectivas de Hacking**\
Participa en contenido que profundiza en la emoción y los desafíos del hacking

**Noticias de Hackeo en Tiempo Real**\
Mantente al día con el mundo del hacking a través de noticias e información en tiempo real

**Últimos Anuncios**\
Mantente informado sobre las nuevas recompensas por bugs que se lanzan y actualizaciones cruciales de la plataforma

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy mismo!

## MacOS Básico

Si no estás familiarizado con macOS, deberías comenzar a aprender los conceptos básicos de macOS:

* Archivos y **permisos especiales de macOS:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* **Usuarios comunes de macOS**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* La **arquitectura** del **kernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Servicios y **protocolos de red comunes de macOS**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Código abierto** de macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Para descargar un `tar.gz`, cambia una URL como [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) a [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM de MacOS

En las empresas, los sistemas **macOS** probablemente serán **gestionados con un MDM**. Por lo tanto, desde la perspectiva de un atacante, es interesante saber **cómo funciona eso**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspección, Depuración y Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Protecciones de Seguridad de MacOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Superficie de Ataque

### Permisos de Archivos

Si un **proceso que se ejecuta como root escribe** un archivo que puede ser controlado por un usuario, el usuario podría abusar de esto para **escalar privilegios**.\
Esto podría ocurrir en las siguientes situaciones:

* El archivo utilizado ya fue creado por un usuario (pertenece al usuario)
* El archivo utilizado es escribible por el usuario debido a un grupo
* El archivo utilizado está dentro de un directorio propiedad del usuario (el usuario podría crear el archivo)
* El archivo utilizado está dentro de un directorio propiedad de root, pero el usuario tiene acceso de escritura sobre él debido a un grupo (el usuario podría crear el archivo)

Poder **crear un archivo** que va a ser **utilizado por root**, permite a un usuario **aprovechar su contenido** o incluso crear **symlinks/hardlinks** para apuntar a otro lugar.

Para este tipo de vulnerabilidades, no olvides **verificar instaladores `.pkg` vulnerables**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Controladores de Aplicaciones de Extensión de Archivo y Esquema de URL

Aplicaciones extrañas registradas por extensiones de archivo podrían ser abusadas y diferentes aplicaciones pueden registrarse para abrir protocolos específicos

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Escalación de Privilegios TCC / SIP de macOS

En macOS, **las aplicaciones y binarios pueden tener permisos** para acceder a carpetas o configuraciones que les otorgan más privilegios que a otros.

Por lo tanto, un atacante que quiera comprometer con éxito una máquina macOS necesitará **escalar sus privilegios TCC** (o incluso **eludir SIP**, dependiendo de sus necesidades).

Estos privilegios generalmente se otorgan en forma de **derechos** con los que la aplicación está firmada, o la aplicación podría solicitar algunos accesos y después de que el **usuario los apruebe**, pueden encontrarse en las **bases de datos TCC**. Otra forma en que un proceso puede obtener estos privilegios es siendo un **hijo de un proceso** con esos **privilegios**, ya que generalmente son **heredados**.

Sigue estos enlaces para encontrar diferentes formas de [**escalar privilegios en TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), para [**eludir TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) y cómo en el pasado [**se ha eludido SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalación de Privilegios Tradicional de macOS

Por supuesto, desde la perspectiva de un equipo rojo, también deberías estar interesado en escalar a root. Revisa la siguiente publicación para algunos consejos:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## Cumplimiento de macOS

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos\_security)

## Referencias

* [**Respuesta a Incidentes de OS X: Scripting y Análisis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Únete al [**Discord de HackenProof**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de bugs.

**Perspectivas de Hacking**\
Participa en contenido que profundiza en la emoción y los desafíos del hacking

**Noticias de Hackeo en Tiempo Real**\
Mantente al día con el mundo del hacking a través de noticias e información en tiempo real

**Últimos Anuncios**\
Mantente informado sobre las nuevas recompensas por bugs que se lanzan y actualizaciones cruciales de la plataforma

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy mismo!

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}
