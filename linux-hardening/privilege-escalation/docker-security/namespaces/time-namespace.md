# Time Namespace

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Información Básica

El espacio de nombres de tiempo en Linux permite desplazamientos por espacio de nombres a los relojes monótonos del sistema y a los relojes de tiempo de arranque. Se utiliza comúnmente en contenedores de Linux para cambiar la fecha/hora dentro de un contenedor y ajustar los relojes después de restaurar desde un punto de control o una instantánea.

## Laboratorio:

### Crear diferentes Espacios de Nombres

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, aseguras que el nuevo espacio de montaje tenga una **vista precisa y aislada de la información del proceso específica de ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (Identificación de Proceso). Los detalles clave y la solución se describen a continuación:

1. **Explicación del Problema**:
- El núcleo de Linux permite a un proceso crear nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (denominado "proceso unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos hijos.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el espacio de nombres de PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que PID 1 tiene el papel especial de adoptar procesos huérfanos. El núcleo de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:
- La salida de PID 1 en un nuevo espacio de nombres conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` falla al intentar asignar un nuevo PID al crear un nuevo proceso, produciendo el error "Cannot allocate memory".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` cree un nuevo proceso después de crear el nuevo espacio de nombres de PID.
- Ejecutar `%unshare -fp /bin/bash%` asegura que el comando `unshare` se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos hijos están entonces contenidos de manera segura dentro de este nuevo espacio de nombres, previniendo la salida prematura de PID 1 y permitiendo la asignación normal de PID.

Al asegurarte de que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos operen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Verifique en qué namespace se encuentra su proceso
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Encontrar todos los espacios de nombres de tiempo

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrar dentro de un espacio de nombres de tiempo
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

{% endhint %}
</details>
{% endhint %}
