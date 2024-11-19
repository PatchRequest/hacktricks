# Sécurité macOS & Escalade de Privilèges

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de bugs !

**Aperçus du Hacking**\
Engagez-vous avec du contenu qui explore le frisson et les défis du hacking

**Actualités de Hacking en Temps Réel**\
Restez à jour avec le monde du hacking en rapide évolution grâce à des nouvelles et des aperçus en temps réel

**Dernières Annonces**\
Restez informé des nouvelles primes de bugs lancées et des mises à jour cruciales des plateformes

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers aujourd'hui !

## MacOS de Base

Si vous n'êtes pas familier avec macOS, vous devriez commencer à apprendre les bases de macOS :

* Fichiers et **permissions spéciales macOS :**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* **Utilisateurs macOS courants**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* L'**architecture** du k**ernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Services et **protocoles réseau macOS courants**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** macOS : [https://opensource.apple.com/](https://opensource.apple.com/)
* Pour télécharger un `tar.gz`, changez une URL telle que [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) en [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM macOS

Dans les entreprises, les systèmes **macOS** seront très probablement **gérés avec un MDM**. Par conséquent, du point de vue d'un attaquant, il est intéressant de savoir **comment cela fonctionne** :

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspection, Débogage et Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Protections de Sécurité macOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Surface d'Attaque

### Permissions de Fichier

Si un **processus s'exécutant en tant que root écrit** un fichier qui peut être contrôlé par un utilisateur, l'utilisateur pourrait en abuser pour **escalader les privilèges**.\
Cela pourrait se produire dans les situations suivantes :

* Le fichier utilisé a déjà été créé par un utilisateur (appartenant à l'utilisateur)
* Le fichier utilisé est modifiable par l'utilisateur en raison d'un groupe
* Le fichier utilisé se trouve dans un répertoire appartenant à l'utilisateur (l'utilisateur pourrait créer le fichier)
* Le fichier utilisé se trouve dans un répertoire appartenant à root mais l'utilisateur a un accès en écriture dessus en raison d'un groupe (l'utilisateur pourrait créer le fichier)

Être capable de **créer un fichier** qui va être **utilisé par root**, permet à un utilisateur de **profiter de son contenu** ou même de créer des **symlinks/hardlinks** pour le pointer vers un autre endroit.

Pour ce type de vulnérabilités, n'oubliez pas de **vérifier les installateurs `.pkg` vulnérables** :

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Gestion des Extensions de Fichier & des Handlers d'URL

Des applications étranges enregistrées par des extensions de fichier pourraient être abusées et différentes applications peuvent être enregistrées pour ouvrir des protocoles spécifiques

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Escalade de Privilèges TCC / SIP macOS

Dans macOS, les **applications et binaires peuvent avoir des permissions** pour accéder à des dossiers ou des paramètres qui les rendent plus privilégiés que d'autres.

Par conséquent, un attaquant qui souhaite compromettre avec succès une machine macOS devra **escalader ses privilèges TCC** (ou même **contourner SIP**, selon ses besoins).

Ces privilèges sont généralement accordés sous forme de **droits** avec lesquels l'application est signée, ou l'application peut demander certains accès et après que **l'utilisateur les approuve**, ils peuvent être trouvés dans les **bases de données TCC**. Une autre façon pour un processus d'obtenir ces privilèges est d'être un **enfant d'un processus** avec ces **privilèges** car ils sont généralement **hérités**.

Suivez ces liens pour trouver différentes façons d'[**escalader les privilèges dans TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), pour [**contourner TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) et comment dans le passé [**SIP a été contourné**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalade de Privilèges Traditionnelle macOS

Bien sûr, du point de vue des équipes rouges, vous devriez également être intéressé par l'escalade vers root. Consultez le post suivant pour quelques indices :

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## Conformité macOS

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos\_security)

## Références

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de bugs !

**Aperçus du Hacking**\
Engagez-vous avec du contenu qui explore le frisson et les défis du hacking

**Actualités de Hacking en Temps Réel**\
Restez à jour avec le monde du hacking en rapide évolution grâce à des nouvelles et des aperçus en temps réel

**Dernières Annonces**\
Restez informé des nouvelles primes de bugs lancées et des mises à jour cruciales des plateformes

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers aujourd'hui !

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
