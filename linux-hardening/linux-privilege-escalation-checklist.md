# Λίστα Ελέγχου - Ανύψωση Δικαιωμάτων Linux

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Εγγραφείτε στον [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server για να επικοινωνήσετε με έμπειρους hackers και κυνηγούς bug bounty!

**Ενημερώσεις Hacking**\
Ασχοληθείτε με περιεχόμενο που εμβαθύνει στην αδρεναλίνη και τις προκλήσεις του hacking

**Ειδήσεις Hack σε Πραγματικό Χρόνο**\
Μείνετε ενημερωμένοι με τον ταχύτατο κόσμο του hacking μέσω ειδήσεων και πληροφοριών σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενημερωμένοι με τις πιο πρόσφατες bug bounties που ξεκινούν και κρίσιμες ενημερώσεις πλατφόρμας

**Εγγραφείτε μαζί μας στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και ξεκινήστε να συνεργάζεστε με κορυφαίους hackers σήμερα!

### **Καλύτερο εργαλείο για αναζήτηση τοπικών διαδρομών ανύψωσης δικαιωμάτων Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Πληροφορίες Συστήματος](privilege-escalation/#system-information)

* [ ] Λάβετε **πληροφορίες OS**
* [ ] Ελέγξτε το [**PATH**](privilege-escalation/#path), υπάρχει **γραφείο που μπορεί να γραφτεί**;
* [ ] Ελέγξτε [**μεταβλητές env**](privilege-escalation/#env-info), υπάρχει κάποια ευαίσθητη λεπτομέρεια;
* [ ] Αναζητήστε [**εκμεταλλεύσεις πυρήνα**](privilege-escalation/#kernel-exploits) **χρησιμοποιώντας scripts** (DirtyCow?)
* [ ] **Ελέγξτε** αν η [**έκδοση sudo** είναι ευάλωτη](privilege-escalation/#sudo-version)
* [ ] [**Η επαλήθευση υπογραφής Dmesg απέτυχε**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Περισσότερη αναγνώριση συστήματος ([ημερομηνία, στατιστικά συστήματος, πληροφορίες cpu, εκτυπωτές](privilege-escalation/#more-system-enumeration))
* [ ] [**Αναγνωρίστε περισσότερες άμυνες**](privilege-escalation/#enumerate-possible-defenses)

### [Δίσκοι](privilege-escalation/#drives)

* [ ] **Λίστα των προσαρτημένων** δίσκων
* [ ] **Κάποιος μη προσαρτημένος δίσκος;**
* [ ] **Κάποια creds στο fstab;**

### [**Εγκατεστημένο Λογισμικό**](privilege-escalation/#installed-software)

* [ ] **Ελέγξτε για**[ **χρήσιμο λογισμικό**](privilege-escalation/#useful-software) **που είναι εγκατεστημένο**
* [ ] **Ελέγξτε για** [**ευάλωτο λογισμικό**](privilege-escalation/#vulnerable-software-installed) **που είναι εγκατεστημένο**

### [Διεργασίες](privilege-escalation/#processes)

* [ ] Υπάρχει κάποιο **άγνωστο λογισμικό που εκτελείται**;
* [ ] Υπάρχει κάποιο λογισμικό που εκτελείται με **περισσότερα δικαιώματα από όσα θα έπρεπε**;
* [ ] Αναζητήστε **εκμεταλλεύσεις εκτελούμενων διεργασιών** (ιδιαίτερα την έκδοση που εκτελείται).
* [ ] Μπορείτε να **τροποποιήσετε το δυαδικό** οποιασδήποτε εκτελούμενης διεργασίας;
* [ ] **Παρακολουθήστε διεργασίες** και ελέγξτε αν κάποια ενδιαφέρουσα διεργασία εκτελείται συχνά.
* [ ] Μπορείτε να **διαβάσετε** κάποια ενδιαφέρουσα **μνήμη διεργασίας** (όπου θα μπορούσαν να αποθηκευτούν κωδικοί πρόσβασης);

### [Προγραμματισμένα/Cron jobs;](privilege-escalation/#scheduled-jobs)

* [ ] Ελέγχεται το [**PATH** ](privilege-escalation/#cron-path) από κάποιο cron και μπορείτε να **γράψετε** σε αυτό;
* [ ] Κάποιο [**wildcard** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)σε ένα cron job;
* [ ] Κάποιο [**τροποποιήσιμο script** ](privilege-escalation/#cron-script-overwriting-and-symlink)εκτελείται ή είναι μέσα σε **τροποποιήσιμο φάκελο**;
* [ ] Έχετε ανιχνεύσει ότι κάποιο **script** θα μπορούσε να είναι ή είναι [**εκτελούμενο** πολύ **συχνά**](privilege-escalation/#frequent-cron-jobs); (κάθε 1, 2 ή 5 λεπτά)

### [Υπηρεσίες](privilege-escalation/#services)

* [ ] Κάποιο **γραφείο .service** που μπορεί να γραφτεί;
* [ ] Κάποιο **δυαδικό που μπορεί να γραφτεί** εκτελείται από μια **υπηρεσία**;
* [ ] Κάποιο **γραφείο που μπορεί να γραφτεί στο systemd PATH**;

### [Χρονοδιακόπτες](privilege-escalation/#timers)

* [ ] Κάποιο **χρονοδιακόπτης που μπορεί να γραφτεί**;

### [Υποδοχές](privilege-escalation/#sockets)

* [ ] Κάποιο **γραφείο .socket** που μπορεί να γραφτεί;
* [ ] Μπορείτε να **επικοινωνήσετε με κάποια υποδοχή**;
* [ ] **HTTP sockets** με ενδιαφέρουσες πληροφορίες;

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Μπορείτε να **επικοινωνήσετε με κάποιο D-Bus**;

### [Δίκτυο](privilege-escalation/#network)

* [ ] Αναγνωρίστε το δίκτυο για να ξέρετε πού βρίσκεστε
* [ ] **Ανοιχτές θύρες που δεν μπορούσατε να αποκτήσετε πρόσβαση πριν** αποκτήσετε shell μέσα στη μηχανή;
* [ ] Μπορείτε να **συλλάβετε κίνηση** χρησιμοποιώντας `tcpdump`;

### [Χρήστες](privilege-escalation/#users)

* [ ] Γενική **αναγνώριση χρηστών/ομάδων**
* [ ] Έχετε **πολύ μεγάλο UID**; Είναι η **μηχανή** **ευάλωτη**;
* [ ] Μπορείτε να [**ανυψώσετε δικαιώματα χάρη σε μια ομάδα**](privilege-escalation/interesting-groups-linux-pe/) στην οποία ανήκετε;
* [ ] Δεδομένα **Clipboard**;
* [ ] Πολιτική Κωδικών Πρόσβασης;
* [ ] Δοκιμάστε να **χρησιμοποιήσετε** κάθε **γνωστό κωδικό πρόσβασης** που έχετε ανακαλύψει προηγουμένως για να συνδεθείτε **με κάθε** δυνατό **χρήστη**. Δοκιμάστε να συνδεθείτε επίσης χωρίς κωδικό πρόσβασης.

### [Γραφείο PATH που μπορεί να γραφτεί](privilege-escalation/#writable-path-abuses)

* [ ] Εάν έχετε **δικαιώματα εγγραφής σε κάποιο φάκελο στο PATH** μπορεί να μπορείτε να ανυψώσετε δικαιώματα

### [Εντολές SUDO και SUID](privilege-escalation/#sudo-and-suid)

* [ ] Μπορείτε να εκτελέσετε **οποιαδήποτε εντολή με sudo**; Μπορείτε να το χρησιμοποιήσετε για να ΔΙΑΒΑΣΕΤΕ, ΓΡΑΨΕΤΕ ή ΕΚΤΕΛΕΣΕΤΕ οτιδήποτε ως root; ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Υπάρχει κάποιο **εκμεταλλεύσιμο SUID δυαδικό**; ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Είναι οι [**εντολές sudo** **περιορισμένες** από **path**; μπορείτε να **παρακάμψετε** τους περιορισμούς](privilege-escalation/#sudo-execution-bypassing-paths);
* [ ] [**Εντολή Sudo/SUID χωρίς καθορισμένο path**](privilege-escalation/#sudo-command-suid-binary-without-command-path);
* [ ] [**SUID δυαδικό που καθορίζει path**](privilege-escalation/#suid-binary-with-command-path); Παράκαμψη
* [ ] [**LD\_PRELOAD vuln**](privilege-escalation/#ld\_preload)
* [ ] [**Έλλειψη .so βιβλιοθήκης σε SUID δυαδικό**](privilege-escalation/#suid-binary-so-injection) από έναν φάκελο που μπορεί να γραφτεί;
* [ ] [**Διαθέσιμα SUDO tokens**](privilege-escalation/#reusing-sudo-tokens); [**Μπορείτε να δημιουργήσετε ένα SUDO token**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than);
* [ ] Μπορείτε να [**διαβάσετε ή να τροποποιήσετε τα αρχεία sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d);
* [ ] Μπορείτε να [**τροποποιήσετε το /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d);
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) εντολή

### [Δυνατότητες](privilege-escalation/#capabilities)

* [ ] Έχει κάποιο δυαδικό κάποια **αναμενόμενη δυνατότητα**;

### [ACLs](privilege-escalation/#acls)

* [ ] Έχει κάποιο αρχείο κάποια **αναμενόμενη ACL**;

### [Ανοιχτές συνεδρίες Shell](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Ενδιαφέροντα παραμετροποιημένα SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Ενδιαφέροντα Αρχεία](privilege-escalation/#interesting-files)

* [ ] **Αρχεία προφίλ** - Διαβάστε ευαίσθητα δεδομένα; Γράψτε σε privesc;
* [ ] **αρχεία passwd/shadow** - Διαβάστε ευαίσθητα δεδομένα; Γράψτε σε privesc;
* [ ] **Ελέγξτε κοινά ενδιαφέροντα φακέλους** για ευαίσθητα δεδομένα
* [ ] **Περίεργη τοποθεσία/Αρχεία που ανήκουν,** μπορεί να έχετε πρόσβαση ή να τροποποιήσετε εκτελέσιμα αρχεία
* [ ] **Τροποποιημένα** στα τελευταία λεπτά
* [ ] **Αρχεία Sqlite DB**
* [ ] **Κρυφά αρχεία**
* [ ] **Script/Δυαδικά στο PATH**
* [ ] **Web αρχεία** (κωδικοί πρόσβασης;)
* [ ] **Αντίγραφα ασφαλείας**;
* [ ] **Γνωστά αρχεία που περιέχουν κωδικούς πρόσβασης**: Χρησιμοποιήστε **Linpeas** και **LaZagne**
* [ ] **Γενική αναζήτηση**

### [**Αρχεία που μπορούν να γραφτούν**](privilege-escalation/#writable-files)

* [ ] **Τροποποιήστε τη βιβλιοθήκη python** για να εκτελέσετε αυθαίρετες εντολές;
* [ ] Μπορείτε να **τροποποιήσετε αρχεία καταγραφής**; **Logtotten** exploit
* [ ] Μπορείτε να **τροποποιήσετε το /etc/sysconfig/network-scripts/**; Centos/Redhat exploit
* [ ] Μπορείτε να [**γράψετε σε αρχεία ini, int.d, systemd ή rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d);

### [**Άλλα κόλπα**](privilege-escalation/#other-tricks)

* [ ] Μπορείτε να [**καταχραστείτε το NFS για να ανυψώσετε δικαιώματα**](privilege-escalation/#nfs-privilege-escalation);
* [ ] Χρειάζεστε να [**ξεφύγετε από μια περιοριστική shell**](privilege-escalation/#escaping-from-restricted-shells);

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Εγγραφείτε στον [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server για να επικοινωνήσετε με έμπειρους hackers και κυνηγούς bug bounty!

**Ενημερώσεις Hacking**\
Ασχοληθείτε με περιεχόμενο που εμβαθύνει στην αδρεναλίνη και τις προκλήσεις του hacking

**Ειδήσεις Hack σε Πραγματικό Χρόνο**\
Μείνετε ενημερωμένοι με τον ταχύτατο κόσμο του hacking μέσω ειδήσεων και πληροφοριών σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενημερωμένοι με τις πιο πρόσφατες bug bounties που ξεκινούν και κρίσιμες ενημερώσεις πλατφόρμας

**Εγγραφείτε μαζί μας στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και ξεκινήστε να συνεργάζεστε με κορυφαίους hackers σήμερα!

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
