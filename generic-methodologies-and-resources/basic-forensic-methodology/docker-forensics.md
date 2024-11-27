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

Υπάρχουν υποψίες ότι κάποιο docker container έχει παραβιαστεί:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Μπορείτε εύκολα **να βρείτε τις τροποποιήσεις που έχουν γίνει σε αυτό το κοντέινερ σε σχέση με την εικόνα** με:
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
Στην προηγούμενη εντολή, το **C** σημαίνει **Αλλαγμένο** και το **A** σημαίνει **Προστιθέμενο**.\
Αν διαπιστώσετε ότι κάποιο ενδιαφέρον αρχείο όπως το `/etc/shadow` έχει τροποποιηθεί, μπορείτε να το κατεβάσετε από το κοντέινερ για να ελέγξετε για κακόβουλη δραστηριότητα με:
```bash
docker cp wordpress:/etc/shadow.
```
Μπορείτε επίσης να **το συγκρίνετε με το πρωτότυπο** εκκινώντας ένα νέο κοντέινερ και εξάγοντας το αρχείο από αυτό:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Αν διαπιστώσετε ότι **κάποιο ύποπτο αρχείο προστέθηκε** μπορείτε να αποκτήσετε πρόσβαση στο κοντέινερ και να το ελέγξετε:
```bash
docker exec -it wordpress bash
```
## Images modifications

Όταν σας δοθεί μια εξαγόμενη εικόνα docker (πιθανώς σε μορφή `.tar`), μπορείτε να χρησιμοποιήσετε [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) για να **εξαγάγετε μια περίληψη των τροποποιήσεων**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Τότε, μπορείτε να **αποσυμπιέσετε** την εικόνα και να **πρόσβαση στα blobs** για να αναζητήσετε ύποπτα αρχεία που μπορεί να έχετε βρει στην ιστορία αλλαγών:
```bash
tar -xf image.tar
```
### Basic Analysis

Μπορείτε να αποκτήσετε **βασικές πληροφορίες** από την εικόνα εκτελώντας:
```bash
docker inspect <image>
```
Μπορείτε επίσης να αποκτήσετε μια περίληψη **ιστορίας αλλαγών** με:
```bash
docker history --no-trunc <image>
```
Μπορείτε επίσης να δημιουργήσετε ένα **dockerfile από μια εικόνα** με:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Για να βρείτε προστιθέμενα/τροποποιημένα αρχεία σε εικόνες docker, μπορείτε επίσης να χρησιμοποιήσετε το [**dive**](https://github.com/wagoodman/dive) (κατεβάστε το από [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) εργαλείο:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Αυτό σας επιτρέπει να **πλοηγηθείτε μέσα από τα διάφορα blobs των εικόνων docker** και να ελέγξετε ποια αρχεία έχουν τροποποιηθεί/προστεθεί. **Κόκκινο** σημαίνει προσθήκη και **κίτρινο** σημαίνει τροποποίηση. Χρησιμοποιήστε **tab** για να μετακινηθείτε στην άλλη προβολή και **space** για να συμπτύξετε/ανοίξετε φακέλους.

Με το die δεν θα μπορείτε να αποκτήσετε πρόσβαση στο περιεχόμενο των διαφόρων σταδίων της εικόνας. Για να το κάνετε αυτό, θα χρειαστεί να **αποσυμπιέσετε κάθε στρώμα και να αποκτήσετε πρόσβαση σε αυτό**.\
Μπορείτε να αποσυμπιέσετε όλα τα στρώματα από μια εικόνα από τον κατάλογο όπου αποσυμπιέστηκε η εικόνα εκτελώντας:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Διαπιστευτήρια από μνήμη

Σημειώστε ότι όταν εκτελείτε ένα docker container μέσα σε έναν host **μπορείτε να δείτε τις διεργασίες που εκτελούνται στο container από τον host** απλά εκτελώντας `ps -ef`

Επομένως (ως root) μπορείτε να **dumpάρετε τη μνήμη των διεργασιών** από τον host και να αναζητήσετε **διαπιστευτήρια** ακριβώς [**όπως στο παρακάτω παράδειγμα**](../../linux-hardening/privilege-escalation/#process-memory).

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Εμβαθύνετε την εμπειρία σας στην **Ασφάλεια Κινητών** με την 8kSec Academy. Κατακτήστε την ασφάλεια iOS και Android μέσω των αυτορυθμιζόμενων μαθημάτων μας και αποκτήστε πιστοποίηση:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
