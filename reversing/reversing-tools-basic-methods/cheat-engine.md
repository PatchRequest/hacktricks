# Cheat Engine

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan valores importantes dentro de la memoria de un juego en ejecución y cambiarlos.\
Cuando lo descargas y lo ejecutas, se te **presenta** un **tutorial** sobre cómo usar la herramienta. Si deseas aprender a usar la herramienta, se recomienda encarecidamente completarlo.

## ¿Qué estás buscando?

![](<../../.gitbook/assets/image (762).png>)

Esta herramienta es muy útil para encontrar **dónde se almacena algún valor** (generalmente un número) **en la memoria** de un programa.\
**Generalmente, los números** se almacenan en forma de **4 bytes**, pero también podrías encontrarlos en formatos **double** o **float**, o puede que desees buscar algo **diferente de un número**. Por esa razón, necesitas asegurarte de **seleccionar** lo que deseas **buscar**:

![](<../../.gitbook/assets/image (324).png>)

También puedes indicar **diferentes** tipos de **búsquedas**:

![](<../../.gitbook/assets/image (311).png>)

También puedes marcar la casilla para **detener el juego mientras escanea la memoria**:

![](<../../.gitbook/assets/image (1052).png>)

### Teclas de acceso rápido

En _**Editar --> Configuración --> Teclas de acceso rápido**_ puedes establecer diferentes **teclas de acceso rápido** para diferentes propósitos, como **detener** el **juego** (lo cual es bastante útil si en algún momento deseas escanear la memoria). Otras opciones están disponibles:

![](<../../.gitbook/assets/image (864).png>)

## Modificando el valor

Una vez que **encontraste** dónde está el **valor** que estás **buscando** (más sobre esto en los siguientes pasos), puedes **modificarlo** haciendo doble clic en él, luego haciendo doble clic en su valor:

![](<../../.gitbook/assets/image (563).png>)

Y finalmente **marcando la casilla** para realizar la modificación en la memoria:

![](<../../.gitbook/assets/image (385).png>)

El **cambio** en la **memoria** se aplicará inmediatamente (ten en cuenta que hasta que el juego no use este valor nuevamente, el valor **no se actualizará en el juego**).

## Buscando el valor

Entonces, vamos a suponer que hay un valor importante (como la vida de tu usuario) que deseas mejorar, y estás buscando este valor en la memoria.

### A través de un cambio conocido

Suponiendo que estás buscando el valor 100, **realizas un escaneo** buscando ese valor y encuentras muchas coincidencias:

![](<../../.gitbook/assets/image (108).png>)

Luego, haces algo para que **el valor cambie**, y **detienes** el juego y **realizas** un **siguiente escaneo**:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine buscará los **valores** que **pasaron de 100 al nuevo valor**. Felicitaciones, **encontraste** la **dirección** del valor que estabas buscando, ahora puedes modificarlo.\
Si aún tienes varios valores, haz algo para modificar nuevamente ese valor y realiza otro "siguiente escaneo" para filtrar las direcciones.

### Valor desconocido, cambio conocido

En el escenario en el que **no conoces el valor** pero sabes **cómo hacer que cambie** (e incluso el valor del cambio), puedes buscar tu número.

Así que, comienza realizando un escaneo de tipo "**Valor inicial desconocido**":

![](<../../.gitbook/assets/image (890).png>)

Luego, haz que el valor cambie, indica **cómo** el **valor** **cambió** (en mi caso, disminuyó en 1) y realiza un **siguiente escaneo**:

![](<../../.gitbook/assets/image (371).png>)

Se te presentarán **todos los valores que fueron modificados de la manera seleccionada**:

![](<../../.gitbook/assets/image (569).png>)

Una vez que hayas encontrado tu valor, puedes modificarlo.

Ten en cuenta que hay un **montón de cambios posibles** y puedes hacer estos **pasos tantas veces como desees** para filtrar los resultados:

![](<../../.gitbook/assets/image (574).png>)

### Dirección de memoria aleatoria - Encontrando el código

Hasta ahora hemos aprendido cómo encontrar una dirección que almacena un valor, pero es muy probable que en **diferentes ejecuciones del juego esa dirección esté en diferentes lugares de la memoria**. Así que vamos a averiguar cómo encontrar siempre esa dirección.

Usando algunos de los trucos mencionados, encuentra la dirección donde tu juego actual está almacenando el valor importante. Luego (deteniendo el juego si lo deseas) haz clic derecho en la **dirección** encontrada y selecciona "**Descubrir qué accede a esta dirección**" o "**Descubrir qué escribe en esta dirección**":

![](<../../.gitbook/assets/image (1067).png>)

La **primera opción** es útil para saber qué **partes** del **código** están **usando** esta **dirección** (lo cual es útil para más cosas como **saber dónde puedes modificar el código** del juego).\
La **segunda opción** es más **específica**, y será más útil en este caso ya que estamos interesados en saber **desde dónde se está escribiendo este valor**.

Una vez que hayas seleccionado una de esas opciones, el **depurador** se **adjuntará** al programa y aparecerá una nueva **ventana vacía**. Ahora, **juega** el **juego** y **modifica** ese **valor** (sin reiniciar el juego). La **ventana** debería **llenarse** con las **direcciones** que están **modificando** el **valor**:

![](<../../.gitbook/assets/image (91).png>)

Ahora que encontraste la dirección que está modificando el valor, puedes **modificar el código a tu antojo** (Cheat Engine te permite modificarlo rápidamente a NOPs):

![](<../../.gitbook/assets/image (1057).png>)

Así que, ahora puedes modificarlo para que el código no afecte tu número, o siempre afecte de manera positiva.

### Dirección de memoria aleatoria - Encontrando el puntero

Siguiendo los pasos anteriores, encuentra dónde está el valor que te interesa. Luego, usando "**Descubrir qué escribe en esta dirección**", averigua qué dirección escribe este valor y haz doble clic en él para obtener la vista de desensamblado:

![](<../../.gitbook/assets/image (1039).png>)

Luego, realiza un nuevo escaneo **buscando el valor hex entre "\[]"** (el valor de $edx en este caso):

![](<../../.gitbook/assets/image (994).png>)

(Si aparecen varios, generalmente necesitas la dirección más pequeña)\
Ahora, hemos **encontrado el puntero que modificará el valor que nos interesa**.

Haz clic en "**Agregar dirección manualmente**":

![](<../../.gitbook/assets/image (990).png>)

Ahora, marca la casilla "Puntero" y agrega la dirección encontrada en el cuadro de texto (en este escenario, la dirección encontrada en la imagen anterior fue "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (392).png>)

(Ten en cuenta cómo la primera "Dirección" se completa automáticamente a partir de la dirección del puntero que introduces)

Haz clic en Aceptar y se creará un nuevo puntero:

![](<../../.gitbook/assets/image (308).png>)

Ahora, cada vez que modifiques ese valor, estarás **modificando el valor importante incluso si la dirección de memoria donde se encuentra el valor es diferente.**

### Inyección de código

La inyección de código es una técnica donde inyectas un fragmento de código en el proceso objetivo, y luego rediriges la ejecución del código para que pase por tu propio código escrito (como darte puntos en lugar de restarlos).

Así que, imagina que has encontrado la dirección que está restando 1 a la vida de tu jugador:

![](<../../.gitbook/assets/image (203).png>)

Haz clic en Mostrar desensamblador para obtener el **código desensamblado**.\
Luego, haz clic en **CTRL+a** para invocar la ventana de Auto ensamblado y selecciona _**Plantilla --> Inyección de código**_

![](<../../.gitbook/assets/image (902).png>)

Completa la **dirección de la instrucción que deseas modificar** (esto generalmente se completa automáticamente):

![](<../../.gitbook/assets/image (744).png>)

Se generará una plantilla:

![](<../../.gitbook/assets/image (944).png>)

Así que, inserta tu nuevo código de ensamblador en la sección "**newmem**" y elimina el código original de "**originalcode**" si no deseas que se ejecute. En este ejemplo, el código inyectado sumará 2 puntos en lugar de restar 1:

![](<../../.gitbook/assets/image (521).png>)

**Haz clic en ejecutar y así sucesivamente y tu código debería ser inyectado en el programa cambiando el comportamiento de la funcionalidad!**

## **Referencias**

* **Tutorial de Cheat Engine, complétalo para aprender a comenzar con Cheat Engine** 

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
