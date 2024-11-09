{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) per costruire e **automatizzare flussi di lavoro** alimentati dagli **strumenti comunitari più avanzati** al mondo.\
Ottieni accesso oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

# Gruppi Sudo/Admin

## **PE - Metodo 1**

**A volte**, **per impostazione predefinita \(o perché alcuni software lo richiedono\)** all'interno del file **/etc/sudoers** puoi trovare alcune di queste righe:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Questo significa che **qualsiasi utente che appartiene al gruppo sudo o admin può eseguire qualsiasi cosa come sudo**.

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```text
sudo su
```
## PE - Metodo 2

Trova tutti i binari suid e controlla se c'è il binario **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Se scopri che il binario pkexec è un binario SUID e appartieni a sudo o admin, probabilmente potresti eseguire binari come sudo utilizzando pkexec. Controlla il contenuto di:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Lì troverai quali gruppi sono autorizzati a eseguire **pkexec** e **per impostazione predefinita** in alcuni linux possono **apparire** alcuni dei gruppi **sudo o admin**.

Per **diventare root puoi eseguire**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Se provi a eseguire **pkexec** e ricevi questo **errore**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Non è perché non hai permessi, ma perché non sei connesso senza una GUI**. E c'è una soluzione per questo problema qui: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Hai bisogno di **2 sessioni ssh diverse**:

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

# Gruppo Wheel

**A volte**, **per impostazione predefinita** all'interno del **file /etc/sudoers** puoi trovare questa riga:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Questo significa che **qualsiasi utente che appartiene al gruppo wheel può eseguire qualsiasi cosa come sudo**.

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```text
sudo su
```
# Gruppo Shadow

Gli utenti del **gruppo shadow** possono **leggere** il **file /etc/shadow**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Quindi, leggi il file e prova a **crackare alcuni hash**.

# Gruppo Disco

Questo privilegio è quasi **equivalente all'accesso root** poiché puoi accedere a tutti i dati all'interno della macchina.

File:`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Nota che usando debugfs puoi anche **scrivere file**. Ad esempio, per copiare `/tmp/asd1.txt` in `/tmp/asd2.txt` puoi fare:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Tuttavia, se provi a **scrivere file di proprietà di root** \(come `/etc/shadow` o `/etc/passwd`\) riceverai un errore di "**Permesso negato**".

# Gruppo Video

Utilizzando il comando `w` puoi scoprire **chi è connesso al sistema** e mostrerà un output simile al seguente:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Il **tty1** significa che l'utente **yossi è connesso fisicamente** a un terminale sulla macchina.

Il **gruppo video** ha accesso per visualizzare l'output dello schermo. Fondamentalmente puoi osservare gli schermi. Per fare ciò, devi **catturare l'immagine corrente sullo schermo** in dati grezzi e ottenere la risoluzione che lo schermo sta utilizzando. I dati dello schermo possono essere salvati in `/dev/fb0` e puoi trovare la risoluzione di questo schermo in `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Per **aprire** l'**immagine raw** puoi usare **GIMP**, selezionare il file **`screen.raw`** e selezionare come tipo di file **Dati immagine raw**:

![](../../.gitbook/assets/image%20%28208%29.png)

Poi modifica la Larghezza e l'Altezza a quelle utilizzate sullo schermo e controlla diversi Tipi di Immagine \(e seleziona quello che mostra meglio lo schermo\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Gruppo Root

Sembra che per impostazione predefinita i **membri del gruppo root** possano avere accesso a **modificare** alcuni file di configurazione dei **servizi** o alcuni file di **librerie** o **altre cose interessanti** che potrebbero essere utilizzate per elevare i privilegi...

**Controlla quali file i membri root possono modificare**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Gruppo Docker

Puoi montare il filesystem root della macchina host su un volume dell'istanza, quindi quando l'istanza si avvia, carica immediatamente un `chroot` in quel volume. Questo ti dà effettivamente i privilegi di root sulla macchina.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# Gruppo lxc/lxd

[lxc - Privilege Escalation](lxd-privilege-escalation.md)


<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) per costruire e **automatizzare flussi di lavoro** alimentati dagli **strumenti comunitari più avanzati** al mondo.\
Accedi oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Impara e pratica Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
