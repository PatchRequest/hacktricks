# macOS Red Teaming

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenez la perspective d'un hacker sur vos applications web, votre réseau et votre cloud**

**Trouvez et signalez des vulnérabilités critiques et exploitables ayant un impact commercial réel.** Utilisez nos 20+ outils personnalisés pour cartographier la surface d'attaque, trouver des problèmes de sécurité qui vous permettent d'escalader les privilèges, et utilisez des exploits automatisés pour collecter des preuves essentielles, transformant votre travail acharné en rapports convaincants.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Abus des MDM

* JAMF Pro : `jamf checkJSSConnection`
* Kandji

Si vous parvenez à **compromettre les identifiants administratifs** pour accéder à la plateforme de gestion, vous pouvez **potentiellement compromettre tous les ordinateurs** en distribuant votre malware sur les machines.

Pour le red teaming dans les environnements MacOS, il est fortement recommandé d'avoir une certaine compréhension du fonctionnement des MDM :

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Utiliser MDM comme C2

Un MDM aura la permission d'installer, de consulter ou de supprimer des profils, d'installer des applications, de créer des comptes administratifs locaux, de définir un mot de passe firmware, de changer la clé FileVault...

Pour exécuter votre propre MDM, vous devez **faire signer votre CSR par un fournisseur** que vous pourriez essayer d'obtenir avec [**https://mdmcert.download/**](https://mdmcert.download/). Et pour exécuter votre propre MDM pour les appareils Apple, vous pourriez utiliser [**MicroMDM**](https://github.com/micromdm/micromdm).

Cependant, pour installer une application sur un appareil inscrit, vous devez toujours qu'elle soit signée par un compte développeur... cependant, lors de l'inscription au MDM, l'**appareil ajoute le certificat SSL du MDM comme CA de confiance**, vous pouvez donc maintenant signer n'importe quoi.

Pour inscrire l'appareil dans un MDM, vous devez installer un fichier **`mobileconfig`** en tant que root, qui pourrait être livré via un fichier **pkg** (vous pourriez le compresser en zip et lorsqu'il est téléchargé depuis Safari, il sera décompressé).

**L'agent Mythic Orthrus** utilise cette technique.

### Abus de JAMF PRO

JAMF peut exécuter des **scripts personnalisés** (scripts développés par l'administrateur système), des **charges utiles natives** (création de compte local, définition de mot de passe EFI, surveillance de fichiers/processus...) et des **MDM** (configurations d'appareil, certificats d'appareil...).

#### Auto-inscription JAMF

Allez sur une page telle que `https://<nom-de-l-entreprise>.jamfcloud.com/enroll/` pour voir s'ils ont **l'auto-inscription activée**. S'ils l'ont, cela pourrait **demander des identifiants pour accéder**.

Vous pourriez utiliser le script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) pour effectuer une attaque par pulvérisation de mots de passe.

De plus, après avoir trouvé des identifiants appropriés, vous pourriez être en mesure de forcer d'autres noms d'utilisateur avec le formulaire suivant :

![](<../../.gitbook/assets/image (107).png>)

#### Authentification des appareils JAMF

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

Le binaire **`jamf`** contenait le secret pour ouvrir le trousseau qui, au moment de la découverte, était **partagé** entre tout le monde et c'était : **`jk23ucnq91jfu9aj`**.\
De plus, jamf **persiste** en tant que **LaunchDaemon** dans **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Prise de contrôle des appareils JAMF

L'**URL** **JSS** (Jamf Software Server) que **`jamf`** utilisera se trouve dans **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ce fichier contient essentiellement l'URL :

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Ainsi, un attaquant pourrait déposer un paquet malveillant (`pkg`) qui **écrase ce fichier** lors de l'installation en définissant l'**URL vers un écouteur Mythic C2 d'un agent Typhon** pour pouvoir maintenant abuser de JAMF en tant que C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Usurpation de JAMF

Pour **usurper la communication** entre un appareil et JMF, vous avez besoin de :

* Le **UUID** de l'appareil : `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* Le **trousseau JAMF** de : `/Library/Application\ Support/Jamf/JAMF.keychain` qui contient le certificat de l'appareil

Avec ces informations, **créez une VM** avec le **UUID** matériel **volé** et avec **SIP désactivé**, déposez le **trousseau JAMF,** **interceptez** l'**agent** Jamf et volez ses informations.

#### Vol de secrets

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Vous pouvez également surveiller l'emplacement `/Library/Application Support/Jamf/tmp/` pour les **scripts personnalisés** que les administrateurs pourraient vouloir exécuter via Jamf, car ils sont **placés ici, exécutés et supprimés**. Ces scripts **pourraient contenir des identifiants**.

Cependant, les **identifiants** pourraient être passés à ces scripts en tant que **paramètres**, donc vous devrez surveiller `ps aux | grep -i jamf` (sans même être root).

Le script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) peut écouter les nouveaux fichiers ajoutés et les nouveaux arguments de processus.

### Accès à distance macOS

Et aussi sur les **protocoles** **réseau** "spéciaux" de **MacOS** :

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Dans certaines occasions, vous constaterez que l'**ordinateur MacOS est connecté à un AD**. Dans ce scénario, vous devriez essayer de **énumérer** l'annuaire actif comme vous en avez l'habitude. Trouvez de l'**aide** dans les pages suivantes :

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Un **outil local MacOS** qui pourrait également vous aider est `dscl` :
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Aussi, il existe des outils préparés pour MacOS afin d'énumérer automatiquement l'AD et de jouer avec kerberos :

* [**Machound**](https://github.com/XMCyber/MacHound) : MacHound est une extension de l'outil d'audit Bloodhound permettant de collecter et d'ingérer les relations Active Directory sur les hôtes MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost) : Bifrost est un projet Objective-C conçu pour interagir avec les API Heimdal krb5 sur macOS. L'objectif du projet est de permettre de meilleurs tests de sécurité autour de Kerberos sur les appareils macOS en utilisant des API natives sans nécessiter d'autres frameworks ou packages sur la cible.
* [**Orchard**](https://github.com/its-a-feature/Orchard) : Outil JavaScript pour l'automatisation (JXA) pour faire de l'énumération Active Directory.

### Informations sur le domaine
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Utilisateurs

Les trois types d'utilisateurs MacOS sont :

* **Utilisateurs Locaux** — Gérés par le service OpenDirectory local, ils ne sont en aucun cas connectés à l'Active Directory.
* **Utilisateurs Réseau** — Utilisateurs Active Directory volatils qui nécessitent une connexion au serveur DC pour s'authentifier.
* **Utilisateurs Mobiles** — Utilisateurs Active Directory avec une sauvegarde locale de leurs identifiants et fichiers.

Les informations locales sur les utilisateurs et les groupes sont stockées dans le dossier _/var/db/dslocal/nodes/Default._\
Par exemple, les informations sur l'utilisateur appelé _mark_ sont stockées dans _/var/db/dslocal/nodes/Default/users/mark.plist_ et les informations sur le groupe _admin_ se trouvent dans _/var/db/dslocal/nodes/Default/groups/admin.plist_.

En plus d'utiliser les bords HasSession et AdminTo, **MacHound ajoute trois nouveaux bords** à la base de données Bloodhound :

* **CanSSH** - entité autorisée à SSH vers l'hôte
* **CanVNC** - entité autorisée à VNC vers l'hôte
* **CanAE** - entité autorisée à exécuter des scripts AppleEvent sur l'hôte
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Plus d'infos sur [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Mot de passe de l'ordinateur$

Obtenez des mots de passe en utilisant :
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Il est possible d'accéder au mot de passe **`Computer$`** à l'intérieur du trousseau de clés Système.

### Over-Pass-The-Hash

Obtenez un TGT pour un utilisateur et un service spécifiques :
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Une fois le TGT rassemblé, il est possible de l'injecter dans la session actuelle avec :
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Avec les tickets de service obtenus, il est possible d'essayer d'accéder aux partages sur d'autres ordinateurs :
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Accéder au Trousseau

Le Trousseau contient très probablement des informations sensibles qui, si elles sont accessibles sans générer d'invite, pourraient aider à faire avancer un exercice de red team :

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Services Externes

Le Red Teaming MacOS est différent d'un Red Teaming Windows classique car généralement **MacOS est intégré à plusieurs plateformes externes directement**. Une configuration courante de MacOS consiste à accéder à l'ordinateur en utilisant **des identifiants synchronisés OneLogin, et à accéder à plusieurs services externes** (comme github, aws...) via OneLogin.

## Techniques Diverses de Red Team

### Safari

Lorsqu'un fichier est téléchargé dans Safari, s'il s'agit d'un fichier "sûr", il sera **ouvert automatiquement**. Par exemple, si vous **téléchargez un zip**, il sera automatiquement décompressé :

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## Références

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenez la perspective d'un hacker sur vos applications web, votre réseau et votre cloud**

**Trouvez et signalez des vulnérabilités critiques et exploitables ayant un impact commercial réel.** Utilisez nos 20+ outils personnalisés pour cartographier la surface d'attaque, trouver des problèmes de sécurité qui vous permettent d'escalader les privilèges, et utilisez des exploits automatisés pour collecter des preuves essentielles, transformant votre travail acharné en rapports convaincants.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
