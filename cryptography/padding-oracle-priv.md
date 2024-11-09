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

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


# CBC - Cipher Block Chaining

Στη λειτουργία CBC, το **προηγούμενο κρυπτογραφημένο μπλοκ χρησιμοποιείται ως IV** για XOR με το επόμενο μπλοκ:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Για να αποκρυπτογραφήσετε το CBC, γίνονται οι **αντίθετες** **λειτουργίες**:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Σημειώστε πώς είναι απαραίτητο να χρησιμοποιήσετε ένα **κλειδί κρυπτογράφησης** και ένα **IV**.

# Μήνυμα Padding

Καθώς η κρυπτογράφηση εκτελείται σε **σταθερούς** **μεγέθους** **μπλοκ**, συνήθως απαιτείται **padding** στο **τελευταίο** **μπλοκ** για να ολοκληρωθεί το μήκος του.\
Συνήθως χρησιμοποιείται το **PKCS7**, το οποίο δημιουργεί ένα padding **επαναλαμβάνοντας** τον **αριθμό** των **byte** που **χρειάζονται** για να **ολοκληρωθεί** το μπλοκ. Για παράδειγμα, αν το τελευταίο μπλοκ λείπουν 3 byte, το padding θα είναι `\x03\x03\x03`.

Ας δούμε περισσότερα παραδείγματα με **2 μπλοκ μήκους 8byte**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Σημειώστε πώς στο τελευταίο παράδειγμα το **τελευταίο μπλοκ ήταν γεμάτο, οπότε δημιουργήθηκε ένα άλλο μόνο με padding**.

# Padding Oracle

Όταν μια εφαρμογή αποκρυπτογραφεί κρυπτογραφημένα δεδομένα, πρώτα θα αποκρυπτογραφήσει τα δεδομένα και στη συνέχεια θα αφαιρέσει το padding. Κατά την καθαριότητα του padding, αν μια **μη έγκυρη padding προκαλέσει μια ανιχνεύσιμη συμπεριφορά**, έχετε μια **ευπάθεια padding oracle**. Η ανιχνεύσιμη συμπεριφορά μπορεί να είναι ένα **σφάλμα**, μια **έλλειψη αποτελεσμάτων** ή μια **αργή απόκριση**.

Αν ανιχνεύσετε αυτή τη συμπεριφορά, μπορείτε να **αποκρυπτογραφήσετε τα κρυπτογραφημένα δεδομένα** και ακόμη και να **κρυπτογραφήσετε οποιοδήποτε καθαρό κείμενο**.

## Πώς να εκμεταλλευτείτε

Μπορείτε να χρησιμοποιήσετε [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) για να εκμεταλλευτείτε αυτό το είδος ευπάθειας ή απλά να κάνετε
```
sudo apt-get install padbuster
```
Για να δοκιμάσετε αν το cookie μιας ιστοσελίδας είναι ευάλωτο, θα μπορούσατε να δοκιμάσετε:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** σημαίνει ότι χρησιμοποιείται **base64** (αλλά υπάρχουν και άλλες διαθέσιμες επιλογές, ελέγξτε το μενού βοήθειας).

Μπορείτε επίσης να **καταχραστείτε αυτήν την ευπάθεια για να κρυπτογραφήσετε νέα δεδομένα. Για παράδειγμα, φανταστείτε ότι το περιεχόμενο του cookie είναι "**_**user=MyUsername**_**", τότε μπορείτε να το αλλάξετε σε "\_user=administrator\_" και να κλιμακώσετε τα δικαιώματα μέσα στην εφαρμογή. Μπορείτε επίσης να το κάνετε χρησιμοποιώντας το `paduster` καθορίζοντας την παράμετρο -plaintext**:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Αν ο ιστότοπος είναι ευάλωτος, το `padbuster` θα προσπαθήσει αυτόματα να βρει πότε συμβαίνει το σφάλμα padding, αλλά μπορείτε επίσης να υποδείξετε το μήνυμα σφάλματος χρησιμοποιώντας την παράμετρο **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## Η θεωρία

Συνοπτικά, μπορείτε να ξεκινήσετε την αποκρυπτογράφηση των κρυπτογραφημένων δεδομένων μαντεύοντας τις σωστές τιμές που μπορούν να χρησιμοποιηθούν για να δημιουργήσουν όλα τα διαφορετικά padding. Στη συνέχεια, η επίθεση padding oracle θα αρχίσει να αποκρυπτογραφεί τα bytes από το τέλος προς την αρχή μαντεύοντας ποια θα είναι η σωστή τιμή που δημιουργεί ένα padding 1, 2, 3, κ.λπ.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Φανταστείτε ότι έχετε κάποιο κρυπτογραφημένο κείμενο που καταλαμβάνει 2 blocks που σχηματίζονται από τα bytes από E0 έως E15.\
Για να αποκρυπτογραφήσετε το τελευταίο block (E8 έως E15), ολόκληρο το block περνάει από την "αποκρυπτογράφηση block cipher" παράγοντας τα ενδιάμεσα bytes I0 έως I15.\
Τέλος, κάθε ενδιάμεσο byte XORed με τα προηγούμενα κρυπτογραφημένα bytes (E0 έως E7). Έτσι:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Τώρα, είναι δυνατόν να τροποποιήσετε το `E7` μέχρι το `C15` να είναι `0x01`, το οποίο θα είναι επίσης ένα σωστό padding. Έτσι, σε αυτή την περίπτωση: `\x01 = I15 ^ E'7`

Έτσι, βρίσκοντας το E'7, είναι δυνατόν να υπολογίσετε το I15: `I15 = 0x01 ^ E'7`

Το οποίο μας επιτρέπει να υπολογίσουμε το C15: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Γνωρίζοντας το C15, τώρα είναι δυνατόν να υπολογίσουμε το C14, αλλά αυτή τη φορά με brute-forcing το padding `\x02\x02`.

Αυτή η BF είναι εξίσου περίπλοκη με την προηγούμενη καθώς είναι δυνατόν να υπολογιστεί το `E''15` του οποίου η τιμή είναι 0x02: `E''7 = \x02 ^ I15` οπότε χρειάζεται απλώς να βρείτε το **`E'14`** που παράγει ένα **`C14` ίσο με `0x02`**.\
Στη συνέχεια, κάντε τα ίδια βήματα για να αποκρυπτογραφήσετε το C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Ακολουθήστε αυτή την αλυσίδα μέχρι να αποκρυπτογραφήσετε ολόκληρο το κρυπτογραφημένο κείμενο.**

## Ανίχνευση της ευπάθειας

Εγγραφείτε και δημιουργήστε έναν λογαριασμό και συνδεθείτε με αυτόν το λογαριασμό.\
Αν συνδέεστε πολλές φορές και πάντα λαμβάνετε το ίδιο cookie, πιθανότατα υπάρχει κάτι λάθος στην εφαρμογή. Το cookie που επιστρέφεται θα πρέπει να είναι μοναδικό κάθε φορά που συνδέεστε. Αν το cookie είναι πάντα το ίδιο, πιθανότατα θα είναι πάντα έγκυρο και δεν θα υπάρχει τρόπος να το ακυρώσετε.

Τώρα, αν προσπαθήσετε να τροποποιήσετε το cookie, μπορείτε να δείτε ότι λαμβάνετε ένα σφάλμα από την εφαρμογή.\
Αλλά αν κάνετε BF το padding (χρησιμοποιώντας το padbuster για παράδειγμα) καταφέρετε να αποκτήσετε ένα άλλο cookie έγκυρο για έναν διαφορετικό χρήστη. Αυτό το σενάριο είναι πολύ πιθανό να είναι ευάλωτο στο padbuster.

## Αναφορές

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
