# macOS SIP

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **Informations de base**

**La protection de l'intégrité du système (SIP)** dans macOS est un mécanisme conçu pour empêcher même les utilisateurs les plus privilégiés de faire des modifications non autorisées dans des dossiers système clés. Cette fonctionnalité joue un rôle crucial dans le maintien de l'intégrité du système en restreignant des actions telles que l'ajout, la modification ou la suppression de fichiers dans des zones protégées. Les principaux dossiers protégés par le SIP incluent :

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Les règles qui régissent le comportement du SIP sont définies dans le fichier de configuration situé à **`/System/Library/Sandbox/rootless.conf`**. Dans ce fichier, les chemins qui sont précédés d'un astérisque (\*) sont désignés comme des exceptions aux restrictions strictes du SIP.

Considérez l'exemple ci-dessous :
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Ce extrait implique que bien que SIP sécurise généralement le **`/usr`** répertoire, il existe des sous-répertoires spécifiques (`/usr/libexec/cups`, `/usr/local`, et `/usr/share/man`) où des modifications sont permises, comme l'indique l'astérisque (\*) précédant leurs chemins.

Pour vérifier si un répertoire ou un fichier est protégé par SIP, vous pouvez utiliser la commande **`ls -lOd`** pour vérifier la présence du drapeau **`restricted`** ou **`sunlnk`**. Par exemple :
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Dans ce cas, le drapeau **`sunlnk`** signifie que le répertoire `/usr/libexec/cups` lui-même **ne peut pas être supprimé**, bien que des fichiers à l'intérieur puissent être créés, modifiés ou supprimés.

D'autre part :
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Ici, le drapeau **`restricted`** indique que le répertoire `/usr/libexec` est protégé par SIP. Dans un répertoire protégé par SIP, les fichiers ne peuvent pas être créés, modifiés ou supprimés.

De plus, si un fichier contient l'attribut **`com.apple.rootless`** en tant qu'**attribut étendu**, ce fichier sera également **protégé par SIP**.

{% hint style="success" %}
Notez que le hook **Sandbox** **`hook_vnode_check_setextattr`** empêche toute tentative de modification de l'attribut étendu **`com.apple.rootless`.**
{% endhint %}

**SIP limite également d'autres actions root** telles que :

* Charger des extensions de noyau non fiables
* Obtenir des ports de tâche pour les processus signés par Apple
* Modifier les variables NVRAM
* Autoriser le débogage du noyau

Les options sont maintenues dans la variable nvram en tant que bitflag (`csr-active-config` sur Intel et `lp-sip0` est lu à partir de l'arbre de périphériques démarré pour ARM). Vous pouvez trouver les drapeaux dans le code source XNU dans `csr.sh` :

<figure><img src="../../../.gitbook/assets/image (1192).png" alt=""><figcaption></figcaption></figure>

### Statut SIP

Vous pouvez vérifier si SIP est activé sur votre système avec la commande suivante :
```bash
csrutil status
```
Si vous devez désactiver SIP, vous devez redémarrer votre ordinateur en mode de récupération (en appuyant sur Commande+R pendant le démarrage), puis exécuter la commande suivante :
```bash
csrutil disable
```
Si vous souhaitez garder SIP activé mais supprimer les protections de débogage, vous pouvez le faire avec :
```bash
csrutil enable --without debug
```
### Autres Restrictions

* **Interdit le chargement des extensions de noyau non signées** (kexts), garantissant que seules les extensions vérifiées interagissent avec le noyau du système.
* **Empêche le débogage** des processus système macOS, protégeant les composants essentiels du système contre l'accès et la modification non autorisés.
* **Inhibe les outils** comme dtrace d'inspecter les processus système, protégeant ainsi davantage l'intégrité du fonctionnement du système.

[**En savoir plus sur les informations SIP dans cette présentation**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **Attributions liées à SIP**

* `com.apple.rootless.xpc.bootstrap`: Contrôler launchd
* `com.apple.rootless.install[.heritable]`: Accéder au système de fichiers
* `com.apple.rootless.kext-management`: `kext_request`
* `com.apple.rootless.datavault.controller`: Gérer UF\_DATAVAULT
* `com.apple.rootless.xpc.bootstrap`: Capacités de configuration XPC
* `com.apple.rootless.xpc.effective-root`: Root via launchd XPC
* `com.apple.rootless.restricted-block-devices`: Accès aux périphériques de bloc bruts
* `com.apple.rootless.internal.installer-equivalent`: Accès illimité au système de fichiers
* `com.apple.rootless.restricted-nvram-variables[.heritable]`: Accès complet à NVRAM
* `com.apple.rootless.storage.label`: Modifier les fichiers restreints par com.apple.rootless xattr avec l'étiquette correspondante
* `com.apple.rootless.volume.VM.label`: Maintenir l'échange VM sur le volume

## Contournements de SIP

Contourner SIP permet à un attaquant de :

* **Accéder aux données utilisateur** : Lire des données sensibles de l'utilisateur comme les mails, les messages et l'historique de Safari de tous les comptes utilisateurs.
* **Contournement de TCC** : Manipuler directement la base de données TCC (Transparence, Consentement et Contrôle) pour accorder un accès non autorisé à la webcam, au microphone et à d'autres ressources.
* **Établir une persistance** : Placer des logiciels malveillants dans des emplacements protégés par SIP, les rendant résistants à la suppression, même par des privilèges root. Cela inclut également la possibilité de falsifier l'outil de suppression de logiciels malveillants (MRT).
* **Charger des extensions de noyau** : Bien qu'il existe des protections supplémentaires, contourner SIP simplifie le processus de chargement d'extensions de noyau non signées.

### Paquets d'Installation

**Les paquets d'installation signés avec le certificat d'Apple** peuvent contourner ses protections. Cela signifie que même les paquets signés par des développeurs standard seront bloqués s'ils tentent de modifier des répertoires protégés par SIP.

### Fichier SIP inexistant

Une faille potentielle est que si un fichier est spécifié dans **`rootless.conf` mais n'existe pas actuellement**, il peut être créé. Les logiciels malveillants pourraient exploiter cela pour **établir une persistance** sur le système. Par exemple, un programme malveillant pourrait créer un fichier .plist dans `/System/Library/LaunchDaemons` s'il est répertorié dans `rootless.conf` mais non présent.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
L'attribution **`com.apple.rootless.install.heritable`** permet de contourner SIP
{% endhint %}

#### [CVE-2019-8561](https://objective-see.org/blog/blog\_0x42.html) <a href="#cve" id="cve"></a>

Il a été découvert qu'il était possible de **changer le paquet d'installation après que le système ait vérifié sa signature** de code et ensuite, le système installerait le paquet malveillant au lieu de l'original. Comme ces actions étaient effectuées par **`system_installd`**, cela permettrait de contourner SIP.

#### [CVE-2020–9854](https://objective-see.org/blog/blog\_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Si un paquet était installé à partir d'une image montée ou d'un disque externe, l'**installateur** **exécuterait** le binaire de **ce système de fichiers** (au lieu d'un emplacement protégé par SIP), ce qui ferait que **`system_installd`** exécuterait un binaire arbitraire.

#### CVE-2021-30892 - Shrootless

[**Des chercheurs de cet article de blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) ont découvert une vulnérabilité dans le mécanisme de protection de l'intégrité du système (SIP) de macOS, surnommée la vulnérabilité 'Shrootless'. Cette vulnérabilité concerne le démon **`system_installd`**, qui a une attribution, **`com.apple.rootless.install.heritable`**, permettant à n'importe lequel de ses processus enfants de contourner les restrictions du système de fichiers de SIP.

Le démon **`system_installd`** installera des paquets qui ont été signés par **Apple**.

Les chercheurs ont découvert que lors de l'installation d'un paquet signé par Apple (.pkg), **`system_installd`** **exécute** tous les **scripts post-installation** inclus dans le paquet. Ces scripts sont exécutés par le shell par défaut, **`zsh`**, qui exécute automatiquement des commandes à partir du fichier **`/etc/zshenv`**, s'il existe, même en mode non interactif. Ce comportement pourrait être exploité par des attaquants : en créant un fichier `/etc/zshenv` malveillant et en attendant que **`system_installd` invoque `zsh`**, ils pourraient effectuer des opérations arbitraires sur l'appareil.

De plus, il a été découvert que **`/etc/zshenv` pourrait être utilisé comme une technique d'attaque générale**, pas seulement pour un contournement de SIP. Chaque profil utilisateur a un fichier `~/.zshenv`, qui se comporte de la même manière que `/etc/zshenv` mais ne nécessite pas de permissions root. Ce fichier pourrait être utilisé comme un mécanisme de persistance, se déclenchant chaque fois que `zsh` démarre, ou comme un mécanisme d'élévation de privilèges. Si un utilisateur admin s'élève à root en utilisant `sudo -s` ou `sudo <commande>`, le fichier `~/.zshenv` serait déclenché, élevant effectivement à root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Dans [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/), il a été découvert que le même processus **`system_installd`** pouvait encore être abusé car il plaçait le **script post-installation à l'intérieur d'un dossier nommé aléatoirement protégé par SIP à l'intérieur de `/tmp`**. Le fait est que **`/tmp` lui-même n'est pas protégé par SIP**, donc il était possible de **monter** une **image virtuelle dessus**, puis l'**installateur** y mettrait le **script post-installation**, **démonterait** l'image virtuelle, **recréerait** tous les **dossiers** et **ajouterait** le **script de post-installation** avec la **charge utile** à exécuter.

#### [fsck\_cs utility](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Une vulnérabilité a été identifiée où **`fsck_cs`** a été induit en erreur pour corrompre un fichier crucial, en raison de sa capacité à suivre **liens symboliques**. Plus précisément, les attaquants ont créé un lien de _`/dev/diskX`_ vers le fichier `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. L'exécution de **`fsck_cs`** sur _`/dev/diskX`_ a conduit à la corruption de `Info.plist`. L'intégrité de ce fichier est vitale pour le SIP (Protection de l'Intégrité du Système) du système d'exploitation, qui contrôle le chargement des extensions de noyau. Une fois corrompu, la capacité de SIP à gérer les exclusions de noyau est compromise.

Les commandes pour exploiter cette vulnérabilité sont :
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
L'exploitation de cette vulnérabilité a de graves implications. Le fichier `Info.plist`, normalement responsable de la gestion des autorisations pour les extensions du noyau, devient inefficace. Cela inclut l'incapacité de mettre sur liste noire certaines extensions, telles que `AppleHWAccess.kext`. Par conséquent, avec le mécanisme de contrôle de SIP hors service, cette extension peut être chargée, accordant un accès en lecture et écriture non autorisé à la RAM du système.

#### [Monter sur des dossiers protégés par SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Il était possible de monter un nouveau système de fichiers sur **des dossiers protégés par SIP pour contourner la protection**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Bypass de l'upgrader (2016)](https://objective-see.org/blog/blog\_0x14.html)

Le système est configuré pour démarrer à partir d'une image disque d'installateur intégrée dans le `Install macOS Sierra.app` pour mettre à niveau le système d'exploitation, en utilisant l'utilitaire `bless`. La commande utilisée est la suivante :
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
La sécurité de ce processus peut être compromise si un attaquant modifie l'image de mise à niveau (`InstallESD.dmg`) avant le démarrage. La stratégie consiste à substituer un chargeur dynamique (dyld) par une version malveillante (`libBaseIA.dylib`). Ce remplacement entraîne l'exécution du code de l'attaquant lorsque l'installateur est lancé.

Le code de l'attaquant prend le contrôle pendant le processus de mise à niveau, exploitant la confiance du système dans l'installateur. L'attaque se poursuit en modifiant l'image `InstallESD.dmg` via le swizzling de méthode, ciblant particulièrement la méthode `extractBootBits`. Cela permet l'injection de code malveillant avant que l'image disque ne soit utilisée.

De plus, au sein de `InstallESD.dmg`, il y a un `BaseSystem.dmg`, qui sert de système de fichiers racine pour le code de mise à niveau. Injecter une bibliothèque dynamique dans cela permet au code malveillant d'opérer dans un processus capable de modifier des fichiers au niveau du système d'exploitation, augmentant considérablement le potentiel de compromission du système.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Dans cette présentation de [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), il est montré comment **`systemmigrationd`** (qui peut contourner SIP) exécute un **bash** et un **perl** script, qui peuvent être abusés via les variables d'environnement **`BASH_ENV`** et **`PERL5OPT`**.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Comme [**détaillé dans cet article de blog**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), un script `postinstall` provenant de `InstallAssistant.pkg` permettait d'exécuter :
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
et il était possible de créer un symlink dans `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` qui permettrait à un utilisateur de **déverrouiller n'importe quel fichier, contournant la protection SIP**.

### **com.apple.rootless.install**

{% hint style="danger" %}
L'attribution **`com.apple.rootless.install`** permet de contourner SIP
{% endhint %}

L'attribution `com.apple.rootless.install` est connue pour contourner la Protection de l'Intégrité du Système (SIP) sur macOS. Cela a été notamment mentionné en relation avec [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

Dans ce cas spécifique, le service XPC du système situé à `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possède cette attribution. Cela permet au processus associé de contourner les contraintes SIP. De plus, ce service présente notamment une méthode qui permet le déplacement de fichiers sans appliquer de mesures de sécurité.

## Instantanés de Système Scellés

Les Instantanés de Système Scellés sont une fonctionnalité introduite par Apple dans **macOS Big Sur (macOS 11)** dans le cadre de son mécanisme de **Protection de l'Intégrité du Système (SIP)** pour fournir une couche de sécurité et de stabilité supplémentaire. Ils sont essentiellement des versions en lecture seule du volume système.

Voici un aperçu plus détaillé :

1. **Système Immutable** : Les Instantanés de Système Scellés rendent le volume système macOS "immutable", ce qui signifie qu'il ne peut pas être modifié. Cela empêche toute modification non autorisée ou accidentelle du système qui pourrait compromettre la sécurité ou la stabilité du système.
2. **Mises à Jour du Logiciel Système** : Lorsque vous installez des mises à jour ou des mises à niveau de macOS, macOS crée un nouvel instantané système. Le volume de démarrage macOS utilise ensuite **APFS (Apple File System)** pour passer à ce nouvel instantané. L'ensemble du processus d'application des mises à jour devient plus sûr et plus fiable, car le système peut toujours revenir à l'instantané précédent si quelque chose ne va pas pendant la mise à jour.
3. **Séparation des Données** : En conjonction avec le concept de séparation des volumes de Données et de Système introduit dans macOS Catalina, la fonctionnalité d'Instantané de Système Scellé garantit que toutes vos données et paramètres sont stockés sur un volume "**Données**" séparé. Cette séparation rend vos données indépendantes du système, ce qui simplifie le processus de mises à jour du système et améliore la sécurité du système.

N'oubliez pas que ces instantanés sont gérés automatiquement par macOS et ne prennent pas d'espace supplémentaire sur votre disque, grâce aux capacités de partage d'espace d'APFS. Il est également important de noter que ces instantanés sont différents des **instantanés de Time Machine**, qui sont des sauvegardes accessibles par l'utilisateur de l'ensemble du système.

### Vérifier les Instantanés

La commande **`diskutil apfs list`** liste les **détails des volumes APFS** et leur disposition :

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   Référence de Conteneur APFS :     disk3
|   Taille (Plafond de Capacité) :      494384795648 B (494.4 Go)
|   Capacité Utilisée par les Volumes :   219214536704 B (219.2 Go) (44.3% utilisé)
|   Capacité Non Allouée :       275170258944 B (275.2 Go) (55.7% libre)
|   |
|   +-&#x3C; Magasin Physique disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   Disque de Magasin Physique APFS :   disk0s2
|   |   Taille :                       494384795648 B (494.4 Go)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   Disque de Volume APFS (Rôle) :   disk3s1 (Système)
</strong>|   |   Nom :                      Macintosh HD (Insensible à la casse)
<strong>|   |   Point de Montage :               /System/Volumes/Update/mnt1
</strong>|   |   Capacité Consommée :         12819210240 B (12.8 Go)
|   |   Scellé :                    Cassé
|   |   FileVault :                 Oui (Déverrouillé)
|   |   Chiffré :                 Non
|   |   |
|   |   Instantané :                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Disque d'Instantané :             disk3s1s1
<strong>|   |   Point de Montage d'Instantané :      /
</strong><strong>|   |   Instantané Scellé :           Oui
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   Disque de Volume APFS (Rôle) :   disk3s5 (Données)
|   Nom :                      Macintosh HD - Données (Insensible à la casse)
<strong>    |   Point de Montage :               /System/Volumes/Data
</strong><strong>    |   Capacité Consommée :         412071784448 B (412.1 Go)
</strong>    |   Scellé :                    Non
|   FileVault :                 Oui (Déverrouillé)
</code></pre>

Dans la sortie précédente, il est possible de voir que les **emplacements accessibles par l'utilisateur** sont montés sous `/System/Volumes/Data`.

De plus, l'**instantané du volume système macOS** est monté dans `/` et il est **scellé** (signé cryptographiquement par le système d'exploitation). Donc, si SIP est contourné et modifié, le **système d'exploitation ne démarrera plus**.

Il est également possible de **vérifier que le sceau est activé** en exécutant :
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
De plus, le disque instantané est également monté en tant que **lecture seule** :
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team GCP (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
