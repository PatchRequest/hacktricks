# macOS Authorizations DB & Authd



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

## **Base de datos de autorizaciones**

La base de datos ubicada en `/var/db/auth.db` es una base de datos utilizada para almacenar permisos para realizar operaciones sensibles. Estas operaciones se realizan completamente en **espacio de usuario** y generalmente son utilizadas por **servicios XPC** que necesitan verificar **si el cliente que llama está autorizado** para realizar cierta acción verificando esta base de datos.

Inicialmente, esta base de datos se crea a partir del contenido de `/System/Library/Security/authorization.plist`. Luego, algunos servicios pueden agregar o modificar esta base de datos para añadir otros permisos.

Las reglas se almacenan en la tabla `rules` dentro de la base de datos y contienen las siguientes columnas:

* **id**: Un identificador único para cada regla, incrementado automáticamente y que sirve como clave primaria.
* **name**: El nombre único de la regla utilizado para identificarla y referenciarla dentro del sistema de autorización.
* **type**: Especifica el tipo de la regla, restringido a los valores 1 o 2 para definir su lógica de autorización.
* **class**: Categoriza la regla en una clase específica, asegurando que sea un número entero positivo.
* "allow" para permitir, "deny" para denegar, "user" si la propiedad de grupo indica un grupo cuya membresía permite el acceso, "rule" indica en un array una regla que debe cumplirse, "evaluate-mechanisms" seguido de un array `mechanisms` que son ya sea integrados o un nombre de un paquete dentro de `/System/Library/CoreServices/SecurityAgentPlugins/` o /Library/Security//SecurityAgentPlugins
* **group**: Indica el grupo de usuarios asociado con la regla para la autorización basada en grupos.
* **kofn**: Representa el parámetro "k-of-n", determinando cuántas subreglas deben ser satisfechas de un número total.
* **timeout**: Define la duración en segundos antes de que la autorización otorgada por la regla expire.
* **flags**: Contiene varias banderas que modifican el comportamiento y las características de la regla.
* **tries**: Limita el número de intentos de autorización permitidos para mejorar la seguridad.
* **version**: Rastrea la versión de la regla para el control de versiones y actualizaciones.
* **created**: Registra la marca de tiempo cuando se creó la regla para fines de auditoría.
* **modified**: Almacena la marca de tiempo de la última modificación realizada a la regla.
* **hash**: Contiene un valor hash de la regla para asegurar su integridad y detectar manipulaciones.
* **identifier**: Proporciona un identificador único en forma de cadena, como un UUID, para referencias externas a la regla.
* **requirement**: Contiene datos serializados que definen los requisitos y mecanismos de autorización específicos de la regla.
* **comment**: Ofrece una descripción o comentario legible por humanos sobre la regla para documentación y claridad.

### Ejemplo
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Además, en [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) es posible ver el significado de `authenticate-admin-nonshared`:
```json
{
'allow-root' : 'false',
'authenticate-user' : 'true',
'class' : 'user',
'comment' : 'Authenticate as an administrator.',
'group' : 'admin',
'session-owner' : 'false',
'shared' : 'false',
'timeout' : '30',
'tries' : '10000',
'version' : '1'
}
```
## Authd

Es un demonio que recibirá solicitudes para autorizar a los clientes a realizar acciones sensibles. Funciona como un servicio XPC definido dentro de la carpeta `XPCServices/` y utiliza para escribir sus registros en `/var/log/authd.log`.

Además, utilizando la herramienta de seguridad es posible probar muchas APIs de `Security.framework`. Por ejemplo, el `AuthorizationExecuteWithPrivileges` ejecutando: `security execute-with-privileges /bin/ls`

Eso hará un fork y ejecutará `/usr/libexec/security_authtrampoline /bin/ls` como root, lo que pedirá permisos en un aviso para ejecutar ls como root:

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

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
