# Docker Forensics

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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Profundiza tu experiencia en **Mobile Security** con 8kSec Academy. Domina la seguridad de iOS y Android a través de nuestros cursos autoguiados y obtén una certificación:

{% embed url="https://academy.8ksec.io/" %}

## Modificación de contenedores

Hay sospechas de que algún contenedor de docker fue comprometido:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Puedes fácilmente **encontrar las modificaciones realizadas a este contenedor con respecto a la imagen** con:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
En el comando anterior, **C** significa **Cambiado** y **A,** **Agregado**.\
Si encuentras que algún archivo interesante como `/etc/shadow` fue modificado, puedes descargarlo del contenedor para verificar actividad maliciosa con:
```bash
docker cp wordpress:/etc/shadow.
```
Puedes también **compararlo con el original** ejecutando un nuevo contenedor y extrayendo el archivo de él:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Si encuentras que **se añadió algún archivo sospechoso**, puedes acceder al contenedor y revisarlo:
```bash
docker exec -it wordpress bash
```
## Imágenes modificadas

Cuando se te proporciona una imagen de docker exportada (probablemente en formato `.tar`), puedes usar [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) para **extraer un resumen de las modificaciones**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Luego, puedes **descomprimir** la imagen y **acceder a los blobs** para buscar archivos sospechosos que puedas haber encontrado en el historial de cambios:
```bash
tar -xf image.tar
```
### Análisis Básico

Puedes obtener **información básica** de la imagen ejecutando:
```bash
docker inspect <image>
```
También puedes obtener un resumen **historia de cambios** con:
```bash
docker history --no-trunc <image>
```
Puedes también generar un **dockerfile a partir de una imagen** con:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Para encontrar archivos añadidos/modificados en imágenes de docker, también puedes usar la [**dive**](https://github.com/wagoodman/dive) (descárgalo de [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) utilidad:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Esto te permite **navegar a través de los diferentes blobs de imágenes de docker** y verificar qué archivos fueron modificados/agregados. **Rojo** significa agregado y **amarillo** significa modificado. Usa **tab** para moverte a la otra vista y **space** para colapsar/abrir carpetas.

Con die no podrás acceder al contenido de las diferentes etapas de la imagen. Para hacerlo, necesitarás **descomprimir cada capa y acceder a ella**.\
Puedes descomprimir todas las capas de una imagen desde el directorio donde se descomprimió la imagen ejecutando:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credenciales de la memoria

Ten en cuenta que cuando ejecutas un contenedor de docker dentro de un host **puedes ver los procesos que se ejecutan en el contenedor desde el host** simplemente ejecutando `ps -ef`

Por lo tanto (como root) puedes **volcar la memoria de los procesos** desde el host y buscar **credenciales** justo [**como en el siguiente ejemplo**](../../linux-hardening/privilege-escalation/#process-memory).

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Profundiza tu experiencia en **Seguridad Móvil** con 8kSec Academy. Domina la seguridad de iOS y Android a través de nuestros cursos autoguiados y obtén certificación:

{% embed url="https://academy.8ksec.io/" %}

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
