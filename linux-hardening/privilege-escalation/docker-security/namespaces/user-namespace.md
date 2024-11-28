# Espacio de Nombres de Usuario

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**repositorios de HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Información Básica

Un espacio de nombres de usuario es una característica del núcleo de Linux que **proporciona aislamiento de las asignaciones de ID de usuario y grupo**, permitiendo que cada espacio de nombres de usuario tenga su **propio conjunto de IDs de usuario y grupo**. Este aislamiento permite que los procesos que se ejecutan en diferentes espacios de nombres de usuario **tengan diferentes privilegios y propiedad**, incluso si comparten los mismos IDs de usuario y grupo numéricamente.

Los espacios de nombres de usuario son particularmente útiles en la contenedorización, donde cada contenedor debe tener su propio conjunto independiente de IDs de usuario y grupo, lo que permite una mejor seguridad y aislamiento entre los contenedores y el sistema host.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres de usuario, **comienza con un conjunto vacío de asignaciones de ID de usuario y grupo**. Esto significa que cualquier proceso que se ejecute en el nuevo espacio de nombres de usuario **no tendrá inicialmente privilegios fuera del espacio de nombres**.
2. Se pueden establecer asignaciones de ID entre los IDs de usuario y grupo en el nuevo espacio de nombres y aquellos en el espacio de nombres padre (o host). Esto **permite que los procesos en el nuevo espacio de nombres tengan privilegios y propiedad correspondientes a los IDs de usuario y grupo en el espacio de nombres padre**. Sin embargo, las asignaciones de ID pueden restringirse a rangos y subconjuntos específicos de IDs, lo que permite un control detallado sobre los privilegios otorgados a los procesos en el nuevo espacio de nombres.
3. Dentro de un espacio de nombres de usuario, **los procesos pueden tener privilegios de root completos (UID 0) para operaciones dentro del espacio de nombres**, mientras que aún tienen privilegios limitados fuera del espacio de nombres. Esto permite que **los contenedores se ejecuten con capacidades similares a root dentro de su propio espacio de nombres sin tener privilegios de root completos en el sistema host**.
4. Los procesos pueden moverse entre espacios de nombres utilizando la llamada al sistema `setns()` o crear nuevos espacios de nombres utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWUSER`. Cuando un proceso se mueve a un nuevo espacio de nombres o crea uno, comenzará a usar las asignaciones de ID de usuario y grupo asociadas con ese espacio de nombres.

## Laboratorio:

### Crear diferentes Espacios de Nombres

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, aseguras que el nuevo espacio de montaje tenga una **vista precisa y aislada de la información del proceso específica de ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (ID de Proceso). Los detalles clave y la solución se describen a continuación:

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
Para usar el espacio de nombres de usuario, el daemon de Docker debe iniciarse con **`--userns-remap=default`** (En ubuntu 14.04, esto se puede hacer modificando `/etc/default/docker` y luego ejecutando `sudo service docker restart`)

### &#x20;Verifica en qué espacio de nombres está tu proceso
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Es posible verificar el mapa de usuarios desde el contenedor de docker con:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
O desde el host con:
```bash
cat /proc/<pid>/uid_map
```
### Encontrar todos los espacios de nombres de usuario

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrar dentro de un espacio de nombres de usuario
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en otro espacio de nombres de proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/user`).

### Crear un nuevo espacio de nombres de usuario (con mapeos)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Recuperando Capacidades

En el caso de los espacios de nombres de usuario, **cuando se crea un nuevo espacio de nombres de usuario, el proceso que entra en el espacio de nombres recibe un conjunto completo de capacidades dentro de ese espacio de nombres**. Estas capacidades permiten al proceso realizar operaciones privilegiadas como **montar** **sistemas de archivos**, crear dispositivos o cambiar la propiedad de archivos, pero **solo dentro del contexto de su espacio de nombres de usuario**.

Por ejemplo, cuando tienes la capacidad `CAP_SYS_ADMIN` dentro de un espacio de nombres de usuario, puedes realizar operaciones que normalmente requieren esta capacidad, como montar sistemas de archivos, pero solo dentro del contexto de tu espacio de nombres de usuario. Cualquier operación que realices con esta capacidad no afectará al sistema host ni a otros espacios de nombres.

{% hint style="warning" %}
Por lo tanto, incluso si obtener un nuevo proceso dentro de un nuevo espacio de nombres de usuario **te dará todas las capacidades de vuelta** (CapEff: 000001ffffffffff), en realidad **solo puedes usar las relacionadas con el espacio de nombres** (montar, por ejemplo) pero no todas. Así que, esto por sí solo no es suficiente para escapar de un contenedor Docker.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
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
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

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
{% endhint %}
