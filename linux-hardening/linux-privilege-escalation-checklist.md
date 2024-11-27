# Liste de contrôle - Élévation de privilèges Linux

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de bugs !

**Aperçus du hacking**\
Engagez-vous avec du contenu qui explore le frisson et les défis du hacking

**Actualités de hacking en temps réel**\
Restez à jour avec le monde du hacking en rapide évolution grâce à des nouvelles et des aperçus en temps réel

**Dernières annonces**\
Restez informé des nouveaux programmes de bug bounty lancés et des mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers aujourd'hui !

### **Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locaux Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informations système](privilege-escalation/#system-information)

* [ ] Obtenez des **informations sur le système d'exploitation**
* [ ] Vérifiez le [**PATH**](privilege-escalation/#path), un **dossier modifiable** ?
* [ ] Vérifiez les [**variables d'environnement**](privilege-escalation/#env-info), des détails sensibles ?
* [ ] Recherchez des [**exploits de noyau**](privilege-escalation/#kernel-exploits) **en utilisant des scripts** (DirtyCow ?)
* [ ] **Vérifiez** si la [**version de sudo** est vulnérable](privilege-escalation/#sudo-version)
* [ ] [**La vérification de signature Dmesg a échoué**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Plus d'énumération système ([date, statistiques système, informations CPU, imprimantes](privilege-escalation/#more-system-enumeration))
* [ ] [**Énumérer plus de défenses**](privilege-escalation/#enumerate-possible-defenses)

### [Disques](privilege-escalation/#drives)

* [ ] **Lister les** disques montés
* [ ] **Un disque non monté ?**
* [ ] **Des identifiants dans fstab ?**

### [**Logiciels installés**](privilege-escalation/#installed-software)

* [ ] **Vérifiez les** [**logiciels utiles**](privilege-escalation/#useful-software) **installés**
* [ ] **Vérifiez les** [**logiciels vulnérables**](privilege-escalation/#vulnerable-software-installed) **installés**

### [Processus](privilege-escalation/#processes)

* [ ] Y a-t-il un **logiciel inconnu en cours d'exécution** ?
* [ ] Y a-t-il un logiciel en cours d'exécution avec **plus de privilèges qu'il ne devrait** ?
* [ ] Recherchez des **exploits de processus en cours d'exécution** (en particulier la version en cours d'exécution).
* [ ] Pouvez-vous **modifier le binaire** de tout processus en cours d'exécution ?
* [ ] **Surveillez les processus** et vérifiez si un processus intéressant s'exécute fréquemment.
* [ ] Pouvez-vous **lire** la **mémoire d'un processus** intéressant (où des mots de passe pourraient être sauvegardés) ?

### [Tâches planifiées/Cron ?](privilege-escalation/#scheduled-jobs)

* [ ] Le [**PATH**](privilege-escalation/#cron-path) est-il modifié par un cron et pouvez-vous **écrire** dedans ?
* [ ] Un [**wildcard**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) dans une tâche cron ?
* [ ] Un [**script modifiable**](privilege-escalation/#cron-script-overwriting-and-symlink) est-il **exécuté** ou est-il dans un **dossier modifiable** ?
* [ ] Avez-vous détecté qu'un **script** pourrait être ou est en cours d'[**exécution très fréquemment**](privilege-escalation/#frequent-cron-jobs) ? (toutes les 1, 2 ou 5 minutes)

### [Services](privilege-escalation/#services)

* [ ] Un fichier **.service** **modifiable** ?
* [ ] Un **binaire modifiable** exécuté par un **service** ?
* [ ] Un **dossier modifiable dans le PATH systemd** ?

### [Timers](privilege-escalation/#timers)

* [ ] Un **timer modifiable** ?

### [Sockets](privilege-escalation/#sockets)

* [ ] Un fichier **.socket** **modifiable** ?
* [ ] Pouvez-vous **communiquer avec un socket** ?
* [ ] **Sockets HTTP** avec des informations intéressantes ?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Pouvez-vous **communiquer avec un D-Bus** ?

### [Réseau](privilege-escalation/#network)

* [ ] Énumérez le réseau pour savoir où vous êtes
* [ ] **Ports ouverts auxquels vous ne pouviez pas accéder avant** d'obtenir un shell à l'intérieur de la machine ?
* [ ] Pouvez-vous **sniffer le trafic** en utilisant `tcpdump` ?

### [Utilisateurs](privilege-escalation/#users)

* [ ] Énumération des utilisateurs/groupes **génériques**
* [ ] Avez-vous un **UID très élevé** ? La **machine** est-elle **vulnérable** ?
* [ ] Pouvez-vous [**escalader les privilèges grâce à un groupe**](privilege-escalation/interesting-groups-linux-pe/) auquel vous appartenez ?
* [ ] Données du **presse-papiers** ?
* [ ] Politique de mot de passe ?
* [ ] Essayez d'**utiliser** chaque **mot de passe connu** que vous avez découvert précédemment pour vous connecter **avec chaque** utilisateur possible. Essayez également de vous connecter sans mot de passe.

### [PATH modifiable](privilege-escalation/#writable-path-abuses)

* [ ] Si vous avez **des privilèges d'écriture sur un dossier dans le PATH**, vous pourriez être en mesure d'escalader les privilèges

### [Commandes SUDO et SUID](privilege-escalation/#sudo-and-suid)

* [ ] Pouvez-vous exécuter **n'importe quelle commande avec sudo** ? Pouvez-vous l'utiliser pour LIRE, ÉCRIRE ou EXÉCUTER quoi que ce soit en tant que root ? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Y a-t-il un **binaire SUID exploitable** ? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Les [**commandes sudo** sont-elles **limitées** par le **path** ? pouvez-vous **contourner** les restrictions](privilege-escalation/#sudo-execution-bypassing-paths) ?
* [ ] [**Binaire Sudo/SUID sans path indiqué**](privilege-escalation/#sudo-command-suid-binary-without-command-path) ?
* [ ] [**Binaire SUID spécifiant le path**](privilege-escalation/#suid-binary-with-command-path) ? Contourner
* [ ] [**Vulnérabilité LD\_PRELOAD**](privilege-escalation/#ld_preload)
* [ ] [**Absence de bibliothèque .so dans le binaire SUID**](privilege-escalation/#suid-binary-so-injection) d'un dossier modifiable ?
* [ ] [**Tokens SUDO disponibles**](privilege-escalation/#reusing-sudo-tokens) ? [**Pouvez-vous créer un token SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than) ?
* [ ] Pouvez-vous [**lire ou modifier les fichiers sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d) ?
* [ ] Pouvez-vous [**modifier /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d) ?
* [ ] Commande [**OpenBSD DOAS**](privilege-escalation/#doas)

### [Capacités](privilege-escalation/#capabilities)

* [ ] Un binaire a-t-il une **capacité inattendue** ?

### [ACLs](privilege-escalation/#acls)

* [ ] Un fichier a-t-il une **ACL inattendue** ?

### [Sessions de shell ouvertes](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL PRNG prévisible - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Valeurs de configuration SSH intéressantes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Fichiers intéressants](privilege-escalation/#interesting-files)

* [ ] **Fichiers de profil** - Lire des données sensibles ? Écrire pour privesc ?
* [ ] **Fichiers passwd/shadow** - Lire des données sensibles ? Écrire pour privesc ?
* [ ] **Vérifiez les dossiers couramment intéressants** pour des données sensibles
* [ ] **Emplacement étrange/Fichiers possédés,** vous pourriez avoir accès ou modifier des fichiers exécutables
* [ ] **Modifié** dans les dernières minutes
* [ ] **Fichiers de base de données Sqlite**
* [ ] **Fichiers cachés**
* [ ] **Scripts/Binaires dans le PATH**
* [ ] **Fichiers Web** (mots de passe ?)
* [ ] **Sauvegardes** ?
* [ ] **Fichiers connus contenant des mots de passe** : Utilisez **Linpeas** et **LaZagne**
* [ ] **Recherche générique**

### [**Fichiers modifiables**](privilege-escalation/#writable-files)

* [ ] **Modifier la bibliothèque python** pour exécuter des commandes arbitraires ?
* [ ] Pouvez-vous **modifier les fichiers journaux** ? Exploit **Logtotten**
* [ ] Pouvez-vous **modifier /etc/sysconfig/network-scripts/** ? Exploit Centos/Redhat
* [ ] Pouvez-vous [**écrire dans des fichiers ini, int.d, systemd ou rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d) ?

### [**Autres astuces**](privilege-escalation/#other-tricks)

* [ ] Pouvez-vous [**abuser de NFS pour escalader les privilèges**](privilege-escalation/#nfs-privilege-escalation) ?
* [ ] Avez-vous besoin de [**vous échapper d'un shell restrictif**](privilege-escalation/#escaping-from-restricted-shells) ?

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de bugs !

**Aperçus du hacking**\
Engagez-vous avec du contenu qui explore le frisson et les défis du hacking

**Actualités de hacking en temps réel**\
Restez à jour avec le monde du hacking en rapide évolution grâce à des nouvelles et des aperçus en temps réel

**Dernières annonces**\
Restez informé des nouveaux programmes de bug bounty lancés et des mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers aujourd'hui !

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
