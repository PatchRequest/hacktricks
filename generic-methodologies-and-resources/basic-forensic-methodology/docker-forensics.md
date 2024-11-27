# Docker Forensics

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Verdiep jou kundigheid in **Mobiele Sekuriteit** met 8kSec Akademie. Beheers iOS en Android sekuriteit deur ons self-gebaseerde kursusse en kry gesertifiseer:

{% embed url="https://academy.8ksec.io/" %}

## Houer wysiging

Daar is vermoedens dat 'n paar docker houer gecompromitteer was:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
U kan maklik **die wysigings wat aan hierdie houer gemaak is ten opsigte van die beeld** vind met:
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
In die vorige opdrag beteken **C** **Verander** en **A,** **Gevind**.\
As jy vind dat 'n interessante lêer soos `/etc/shadow` gewysig is, kan jy dit van die houer aflaai om vir kwaadwillige aktiwiteit te kyk met:
```bash
docker cp wordpress:/etc/shadow.
```
Jy kan dit ook **vergelyk met die oorspronklike een** deur 'n nuwe houer te laat loop en die lêer daaruit te onttrek:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
As jy vind dat **'n paar verdagte lêer bygevoeg is** kan jy die houer betree en dit nagaan:
```bash
docker exec -it wordpress bash
```
## Beeld wysigings

Wanneer jy 'n uitgevoerde docker beeld ontvang (waarskynlik in `.tar` formaat) kan jy [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) gebruik om **'n opsomming van die wysigings te onttrek**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Dan kan jy die **dekomprimeer** die beeld en **toegang tot die blobs** verkry om te soek na verdagte lêers wat jy in die veranderinge geskiedenis mag gevind het:
```bash
tar -xf image.tar
```
### Basiese Analise

Jy kan **basiese inligting** van die beeld verkry deur:
```bash
docker inspect <image>
```
U kan ook 'n opsomming **geskiedenis van veranderinge** kry met:
```bash
docker history --no-trunc <image>
```
U kan ook 'n **dockerfile uit 'n beeld** genereer met:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Om bygevoegde/gewijzigde lêers in docker beelde te vind, kan jy ook die [**dive**](https://github.com/wagoodman/dive) (aflaai dit van [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) nut gebruik:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Dit stel jou in staat om **deur die verskillende blobs van docker beelde te navigeer** en te kyk watter lêers gewysig/gevoeg is. **Rooi** beteken gevoeg en **geel** beteken gewysig. Gebruik **tab** om na die ander weergawe te beweeg en **spasie** om vouers in te klap/open.

Met dit sal jy nie toegang hê tot die inhoud van die verskillende fases van die beeld nie. Om dit te doen, sal jy **elke laag moet dekomprimeer en toegang verkry**.\
Jy kan al die lae van 'n beeld dekomprimeer vanaf die gids waar die beeld gedecomprimeer is deur die volgende uit te voer:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Kredensiale uit geheue

Let daarop dat wanneer jy 'n docker-container binne 'n gasheer uitvoer, **jy die prosesse wat op die container loop vanaf die gasheer kan sien** deur net `ps -ef` te loop.

Daarom (as root) kan jy **die geheue van die prosesse** vanaf die gasheer dump en soek na **kredensiale** net [**soos in die volgende voorbeeld**](../../linux-hardening/privilege-escalation/#process-memory).

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Verdiep jou kundigheid in **Mobiele Sekuriteit** met 8kSec Akademie. Meester iOS en Android sekuriteit deur ons self-gebaseerde kursusse en kry gesertifiseer:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
