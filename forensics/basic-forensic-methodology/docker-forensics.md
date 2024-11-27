# Docker Forensics

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Vertiefen Sie Ihr Fachwissen in **Mobiler Sicherheit** mit der 8kSec Akademie. Meistern Sie die Sicherheit von iOS und Android durch unsere selbstgesteuerten Kurse und erhalten Sie ein Zertifikat:

{% embed url="https://academy.8ksec.io/" %}

## Container-Modifikation

Es gibt Verdachtsmomente, dass ein bestimmter Docker-Container kompromittiert wurde:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Sie können leicht **die Änderungen, die an diesem Container im Hinblick auf das Image vorgenommen wurden, finden** mit:
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
In dem vorherigen Befehl bedeutet **C** **Changed** und **A,** **Added**.\
Wenn Sie feststellen, dass eine interessante Datei wie `/etc/shadow` geändert wurde, können Sie sie aus dem Container herunterladen, um nach bösartiger Aktivität zu suchen mit:
```bash
docker cp wordpress:/etc/shadow.
```
Du kannst es auch **mit dem Original vergleichen**, indem du einen neuen Container startest und die Datei daraus extrahierst:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Wenn Sie feststellen, dass **eine verdächtige Datei hinzugefügt wurde**, können Sie auf den Container zugreifen und ihn überprüfen:
```bash
docker exec -it wordpress bash
```
## Images modifications

Wenn Ihnen ein exportiertes Docker-Image (wahrscheinlich im `.tar`-Format) gegeben wird, können Sie [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) verwenden, um **eine Zusammenfassung der Modifikationen** zu **extrahieren**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Dann können Sie das Image **dekomprimieren** und die **Blobs** zugreifen, um nach verdächtigen Dateien zu suchen, die Sie möglicherweise in der Änderungsverlauf gefunden haben:
```bash
tar -xf image.tar
```
### Grundlegende Analyse

Sie können **grundlegende Informationen** aus dem Image erhalten, indem Sie Folgendes ausführen:
```bash
docker inspect <image>
```
Sie können auch eine Zusammenfassung **der Änderungsverläufe** mit folgendem Befehl erhalten:
```bash
docker history --no-trunc <image>
```
Sie können auch ein **Dockerfile aus einem Image** mit folgendem Befehl generieren:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Um hinzugefügte/ändernde Dateien in Docker-Images zu finden, können Sie auch das [**dive**](https://github.com/wagoodman/dive) (laden Sie es von [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) Dienstprogramm verwenden:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Dies ermöglicht es Ihnen, **durch die verschiedenen Blobs von Docker-Images zu navigieren** und zu überprüfen, welche Dateien geändert/hinzugefügt wurden. **Rot** bedeutet hinzugefügt und **gelb** bedeutet geändert. Verwenden Sie **Tab**, um zur anderen Ansicht zu wechseln, und **Leertaste**, um Ordner zu minimieren/öffnen.

Mit dies werden Sie nicht in der Lage sein, auf den Inhalt der verschiedenen Stufen des Images zuzugreifen. Um dies zu tun, müssen Sie **jede Schicht dekomprimieren und darauf zugreifen**.\
Sie können alle Schichten eines Images aus dem Verzeichnis, in dem das Image dekomprimiert wurde, dekomprimieren, indem Sie Folgendes ausführen:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Anmeldeinformationen aus dem Speicher

Beachten Sie, dass Sie, wenn Sie einen Docker-Container auf einem Host ausführen, **die Prozesse, die im Container laufen, vom Host aus sehen können**, indem Sie einfach `ps -ef` ausführen.

Daher können Sie (als Root) **den Speicher der Prozesse** vom Host aus dumpen und nach **Anmeldeinformationen** suchen, genau [**wie im folgenden Beispiel**](../../linux-hardening/privilege-escalation/#process-memory).

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Vertiefen Sie Ihr Fachwissen in **Mobile Security** mit der 8kSec Academy. Meistern Sie die Sicherheit von iOS und Android durch unsere selbstgesteuerten Kurse und lassen Sie sich zertifizieren:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
