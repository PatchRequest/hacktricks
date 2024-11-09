# Otros trucos web

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Obtén la perspectiva de un hacker sobre tus aplicaciones web, red y nube

**Encuentra y reporta vulnerabilidades críticas y explotables con un impacto real en el negocio.** Usa nuestras más de 20 herramientas personalizadas para mapear la superficie de ataque, encontrar problemas de seguridad que te permitan escalar privilegios y usar exploits automatizados para recopilar evidencia esencial, convirtiendo tu arduo trabajo en informes persuasivos.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

### Cabecera Host

Varias veces el back-end confía en la **cabecera Host** para realizar algunas acciones. Por ejemplo, podría usar su valor como el **dominio para enviar un restablecimiento de contraseña**. Así que cuando recibes un correo electrónico con un enlace para restablecer tu contraseña, el dominio que se está utilizando es el que pusiste en la cabecera Host. Luego, puedes solicitar el restablecimiento de contraseña de otros usuarios y cambiar el dominio a uno controlado por ti para robar sus códigos de restablecimiento de contraseña. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Ten en cuenta que es posible que ni siquiera necesites esperar a que el usuario haga clic en el enlace de restablecimiento de contraseña para obtener el token, ya que incluso **los filtros de spam u otros dispositivos/bots intermedios pueden hacer clic en él para analizarlo**.
{% endhint %}

### Booleanos de sesión

A veces, cuando completas correctamente alguna verificación, el back-end **simplemente agrega un booleano con el valor "True" a un atributo de seguridad de tu sesión**. Luego, un endpoint diferente sabrá si pasaste esa verificación con éxito.\
Sin embargo, si **pasas la verificación** y tu sesión recibe ese valor "True" en el atributo de seguridad, puedes intentar **acceder a otros recursos** que **dependen del mismo atributo** pero a los que **no deberías tener permisos** para acceder. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funcionalidad de registro

Intenta registrarte como un usuario ya existente. También prueba usando caracteres equivalentes (puntos, muchos espacios y Unicode).

### Toma de control de correos electrónicos

Registra un correo electrónico, antes de confirmarlo cambia el correo, luego, si el nuevo correo de confirmación se envía al primer correo registrado, puedes tomar el control de cualquier correo. O si puedes habilitar el segundo correo confirmando el primero, también puedes tomar el control de cualquier cuenta.

### Acceso al servicio interno de atención al cliente de empresas que usan Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Método TRACE

Los desarrolladores pueden olvidar deshabilitar varias opciones de depuración en el entorno de producción. Por ejemplo, el método HTTP `TRACE` está diseñado para fines de diagnóstico. Si está habilitado, el servidor web responderá a las solicitudes que utilicen el método `TRACE` repitiendo en la respuesta la solicitud exacta que se recibió. Este comportamiento a menudo es inofensivo, pero ocasionalmente conduce a la divulgación de información, como el nombre de los encabezados de autenticación internos que pueden ser añadidos a las solicitudes por proxies inversos.![Imagen para la publicación](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Imagen para la publicación](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Obtén la perspectiva de un hacker sobre tus aplicaciones web, red y nube

**Encuentra y reporta vulnerabilidades críticas y explotables con un impacto real en el negocio.** Usa nuestras más de 20 herramientas personalizadas para mapear la superficie de ataque, encontrar problemas de seguridad que te permitan escalar privilegios y usar exploits automatizados para recopilar evidencia esencial, convirtiendo tu arduo trabajo en informes persuasivos.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}
