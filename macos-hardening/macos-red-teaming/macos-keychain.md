# macOS Keychain

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

## Main Keychains

* The **User Keychain** (`~/Library/Keychains/login.keychain-db`), que se utiliza para almacenar **credenciales específicas del usuario** como contraseñas de aplicaciones, contraseñas de internet, certificados generados por el usuario, contraseñas de red y claves públicas/privadas generadas por el usuario.
* The **System Keychain** (`/Library/Keychains/System.keychain`), que almacena **credenciales a nivel de sistema** como contraseñas de WiFi, certificados raíz del sistema, claves privadas del sistema y contraseñas de aplicaciones del sistema.
* Es posible encontrar otros componentes como certificados en `/System/Library/Keychains/*`
* En **iOS** solo hay un **Keychain** ubicado en `/private/var/Keychains/`. Esta carpeta también contiene bases de datos para el `TrustStore`, autoridades de certificados (`caissuercache`) y entradas de OSCP (`ocspache`).
* Las aplicaciones estarán restringidas en el llavero solo a su área privada basada en su identificador de aplicación.

### Password Keychain Access

Estos archivos, aunque no tienen protección inherente y pueden ser **descargados**, están encriptados y requieren la **contraseña en texto plano del usuario para ser desencriptados**. Se podría usar una herramienta como [**Chainbreaker**](https://github.com/n0fate/chainbreaker) para la desencriptación.

## Keychain Entries Protections

### ACLs

Cada entrada en el llavero está gobernada por **Listas de Control de Acceso (ACLs)** que dictan quién puede realizar varias acciones en la entrada del llavero, incluyendo:

* **ACLAuhtorizationExportClear**: Permite al titular obtener el texto claro del secreto.
* **ACLAuhtorizationExportWrapped**: Permite al titular obtener el texto claro encriptado con otra contraseña proporcionada.
* **ACLAuhtorizationAny**: Permite al titular realizar cualquier acción.

Las ACLs están acompañadas por una **lista de aplicaciones de confianza** que pueden realizar estas acciones sin solicitar confirmación. Esto podría ser:

* **N`il`** (no se requiere autorización, **todos son de confianza**)
* Una lista **vacía** (**nadie** es de confianza)
* **Lista** de **aplicaciones** específicas.

Además, la entrada puede contener la clave **`ACLAuthorizationPartitionID`,** que se utiliza para identificar el **teamid, apple,** y **cdhash.**

* Si se especifica el **teamid**, entonces para **acceder al valor de la entrada** **sin** un **mensaje de confirmación**, la aplicación utilizada debe tener el **mismo teamid**.
* Si se especifica el **apple**, entonces la aplicación necesita estar **firmada** por **Apple**.
* Si se indica el **cdhash**, entonces la **aplicación** debe tener el **cdhash** específico.

### Creating a Keychain Entry

Cuando se crea una **nueva** **entrada** usando **`Keychain Access.app`**, se aplican las siguientes reglas:

* Todas las aplicaciones pueden encriptar.
* **Ninguna aplicación** puede exportar/desencriptar (sin solicitar al usuario).
* Todas las aplicaciones pueden ver la verificación de integridad.
* Ninguna aplicación puede cambiar las ACLs.
* El **partitionID** se establece en **`apple`**.

Cuando una **aplicación crea una entrada en el llavero**, las reglas son ligeramente diferentes:

* Todas las aplicaciones pueden encriptar.
* Solo la **aplicación que crea** (o cualquier otra aplicación añadida explícitamente) puede exportar/desencriptar (sin solicitar al usuario).
* Todas las aplicaciones pueden ver la verificación de integridad.
* Ninguna aplicación puede cambiar las ACLs.
* El **partitionID** se establece en **`teamid:[teamID aquí]`**.

## Accessing the Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
La **enumeración y volcado de secretos** del **keychain** que **no generará un aviso** se puede hacer con la herramienta [**LockSmith**](https://github.com/its-a-feature/LockSmith)

Otros puntos finales de API se pueden encontrar en el código fuente de [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity\_keychain/libsecurity\_keychain-55017/lib/SecKeychain.h.auto.html).
{% endhint %}

Lista y obtén **info** sobre cada entrada del keychain usando el **Security Framework** o también podrías revisar la herramienta de línea de comandos de código abierto de Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Algunos ejemplos de API:

* La API **`SecItemCopyMatching`** proporciona información sobre cada entrada y hay algunos atributos que puedes establecer al usarla:
* **`kSecReturnData`**: Si es verdadero, intentará descifrar los datos (configúralo en falso para evitar posibles ventanas emergentes)
* **`kSecReturnRef`**: También obtén referencia al elemento del keychain (configúralo en verdadero en caso de que más tarde veas que puedes descifrar sin ventana emergente)
* **`kSecReturnAttributes`**: Obtén metadatos sobre las entradas
* **`kSecMatchLimit`**: Cuántos resultados devolver
* **`kSecClass`**: Qué tipo de entrada del keychain

Obtén **ACLs** de cada entrada:

* Con la API **`SecAccessCopyACLList`** puedes obtener el **ACL para el elemento del keychain**, y devolverá una lista de ACLs (como `ACLAuhtorizationExportClear` y los otros mencionados anteriormente) donde cada lista tiene:
* Descripción
* **Lista de Aplicaciones de Confianza**. Esto podría ser:
* Una app: /Applications/Slack.app
* Un binario: /usr/libexec/airportd
* Un grupo: group://AirPort

Exporta los datos:

* La API **`SecKeychainItemCopyContent`** obtiene el texto plano
* La API **`SecItemExport`** exporta las claves y certificados, pero puede que tengas que establecer contraseñas para exportar el contenido cifrado

Y estos son los **requisitos** para poder **exportar un secreto sin un aviso**:

* Si hay **1+ aplicaciones de confianza** listadas:
* Necesitas las **autorizaciones** apropiadas (**`Nil`**, o ser **parte** de la lista permitida de aplicaciones en la autorización para acceder a la información secreta)
* Necesitas que la firma de código coincida con **PartitionID**
* Necesitas que la firma de código coincida con la de una **aplicación de confianza** (o ser miembro del grupo de acceso al keychain correcto)
* Si **todas las aplicaciones son de confianza**:
* Necesitas las **autorizaciones** apropiadas
* Necesitas que la firma de código coincida con **PartitionID**
* Si **no hay PartitionID**, entonces esto no es necesario

{% hint style="danger" %}
Por lo tanto, si hay **1 aplicación listada**, necesitas **inyectar código en esa aplicación**.

Si **apple** está indicado en el **partitionID**, podrías acceder a él con **`osascript`** así que cualquier cosa que confíe en todas las aplicaciones con apple en el partitionID. **`Python`** también podría usarse para esto.
{% endhint %}

### Dos atributos adicionales

* **Invisible**: Es una bandera booleana para **ocultar** la entrada de la aplicación **UI** del Keychain
* **General**: Es para almacenar **metadatos** (por lo que NO ESTÁ CIFRADO)
* Microsoft estaba almacenando en texto plano todos los tokens de actualización para acceder a puntos finales sensibles.

## Referencias

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
