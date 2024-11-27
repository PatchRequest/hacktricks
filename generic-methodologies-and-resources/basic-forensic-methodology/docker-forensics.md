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

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}

## Container modification

Postoje sumnje da je neki docker kontejner bio kompromitovan:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Možete lako **pronaći izmene koje su izvršene na ovom kontejneru u vezi sa slikom** sa:
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
U prethodnoj komandi **C** znači **Promenjeno** i **A,** **Dodato**.\
Ako otkrijete da je neki zanimljiv fajl kao što je `/etc/shadow` izmenjen, možete ga preuzeti iz kontejnera da proverite za malicioznu aktivnost sa:
```bash
docker cp wordpress:/etc/shadow.
```
Možete takođe **uporediti sa originalnom verzijom** pokretanjem novog kontejnera i ekstrakcijom datoteke iz njega:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Ako otkrijete da je **neki sumnjiv fajl dodat** možete pristupiti kontejneru i proveriti ga:
```bash
docker exec -it wordpress bash
```
## Izmene slika

Kada dobijete eksportovanu docker sliku (verovatno u `.tar` formatu), možete koristiti [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) da **izvučete sažetak izmena**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Zatim, možete **dekompresovati** sliku i **pristupiti blobovima** da biste pretražili sumnjive datoteke koje ste možda pronašli u istoriji promena:
```bash
tar -xf image.tar
```
### Osnovna Analiza

Možete dobiti **osnovne informacije** iz slike pokretanjem:
```bash
docker inspect <image>
```
Možete takođe dobiti sažetak **istorije promena** sa:
```bash
docker history --no-trunc <image>
```
Možete takođe generisati **dockerfile iz slike** sa:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Da biste pronašli dodate/izmene datoteke u docker slikama, možete koristiti [**dive**](https://github.com/wagoodman/dive) (preuzmite ga sa [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) alata:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Ovo vam omogućava da **navigirate kroz različite blob-ove docker slika** i proverite koji su fajlovi modifikovani/dodati. **Crvena** znači dodato, a **žuta** znači modifikovano. Koristite **tab** da pređete na drugi prikaz i **space** da sažmete/otvorite foldere.

Sa die nećete moći da pristupite sadržaju različitih faza slike. Da biste to uradili, moraćete da **dekompresujete svaki sloj i pristupite mu**.\
Možete dekompresovati sve slojeve iz slike iz direktorijuma gde je slika dekompresovana izvršavajući:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Kredencijali iz memorije

Napomena da kada pokrenete docker kontejner unutar hosta **možete videti procese koji se izvršavaju na kontejneru iz hosta** jednostavno pokretanjem `ps -ef`

Stoga (kao root) možete **izvršiti dump memorije procesa** iz hosta i pretražiti **kredencijale** baš [**kao u sledećem primeru**](../../linux-hardening/privilege-escalation/#process-memory).

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Produbite svoje znanje u **Mobilnoj Bezbednosti** sa 8kSec Akademijom. Savladajte iOS i Android bezbednost kroz naše kurseve koji se mogu pratiti sopstvenim tempom i dobijte sertifikat:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
