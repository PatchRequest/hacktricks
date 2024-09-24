# macOS Keychain

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Main Keychains

* Le **trousseau d'accès utilisateur** (`~/Library/Keychains/login.keychain-db`), qui est utilisé pour stocker les **identifiants spécifiques à l'utilisateur** tels que les mots de passe d'application, les mots de passe Internet, les certificats générés par l'utilisateur, les mots de passe réseau et les clés publiques/privées générées par l'utilisateur.
* Le **trousseau d'accès système** (`/Library/Keychains/System.keychain`), qui stocke les **identifiants à l'échelle du système** tels que les mots de passe WiFi, les certificats racine du système, les clés privées du système et les mots de passe d'application du système.
* Il est possible de trouver d'autres composants comme des certificats dans `/System/Library/Keychains/*`
* Dans **iOS**, il n'y a qu'un seul **trousseau** situé dans `/private/var/Keychains/`. Ce dossier contient également des bases de données pour le `TrustStore`, les autorités de certification (`caissuercache`) et les entrées OSCP (`ocspache`).
* Les applications seront restreintes dans le trousseau uniquement à leur zone privée en fonction de leur identifiant d'application.

### Password Keychain Access

Ces fichiers, bien qu'ils n'aient pas de protection inhérente et puissent être **téléchargés**, sont chiffrés et nécessitent le **mot de passe en clair de l'utilisateur pour être déchiffrés**. Un outil comme [**Chainbreaker**](https://github.com/n0fate/chainbreaker) pourrait être utilisé pour le déchiffrement.

## Keychain Entries Protections

### ACLs

Chaque entrée dans le trousseau est régie par des **Listes de Contrôle d'Accès (ACLs)** qui dictent qui peut effectuer diverses actions sur l'entrée du trousseau, y compris :

* **ACLAuhtorizationExportClear** : Permet au titulaire d'obtenir le texte clair du secret.
* **ACLAuhtorizationExportWrapped** : Permet au titulaire d'obtenir le texte clair chiffré avec un autre mot de passe fourni.
* **ACLAuhtorizationAny** : Permet au titulaire d'effectuer n'importe quelle action.

Les ACLs sont également accompagnées d'une **liste d'applications de confiance** qui peuvent effectuer ces actions sans demande. Cela pourrait être :

* **N`il`** (aucune autorisation requise, **tout le monde est de confiance**)
* Une liste **vide** (**personne** n'est de confiance)
* **Liste** d'**applications** spécifiques.

De plus, l'entrée peut contenir la clé **`ACLAuthorizationPartitionID`,** qui est utilisée pour identifier le **teamid, apple,** et **cdhash.**

* Si le **teamid** est spécifié, alors pour **accéder à la valeur de l'entrée** **sans** **demande**, l'application utilisée doit avoir le **même teamid**.
* Si le **apple** est spécifié, alors l'application doit être **signée** par **Apple**.
* Si le **cdhash** est indiqué, alors l'**application** doit avoir le **cdhash** spécifique.

### Creating a Keychain Entry

Lorsque **une nouvelle** **entrée** est créée à l'aide de **`Keychain Access.app`**, les règles suivantes s'appliquent :

* Toutes les applications peuvent chiffrer.
* **Aucune application** ne peut exporter/déchiffrer (sans demander à l'utilisateur).
* Toutes les applications peuvent voir le contrôle d'intégrité.
* Aucune application ne peut changer les ACLs.
* Le **partitionID** est défini sur **`apple`**.

Lorsque **une application crée une entrée dans le trousseau**, les règles sont légèrement différentes :

* Toutes les applications peuvent chiffrer.
* Seule l'**application créatrice** (ou toute autre application explicitement ajoutée) peut exporter/déchiffrer (sans demander à l'utilisateur).
* Toutes les applications peuvent voir le contrôle d'intégrité.
* Aucune application ne peut changer les ACLs.
* Le **partitionID** est défini sur **`teamid:[teamID ici]`**.

## Accessing the Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
L'**énumération et l'extraction** de secrets qui **ne généreront pas d'invite** peuvent être effectuées avec l'outil [**LockSmith**](https://github.com/its-a-feature/LockSmith)

D'autres points de terminaison API peuvent être trouvés dans le code source de [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity\_keychain/libsecurity\_keychain-55017/lib/SecKeychain.h.auto.html).
{% endhint %}

Listez et obtenez des **informations** sur chaque entrée de trousseau en utilisant le **Security Framework** ou vous pouvez également vérifier l'outil cli open source d'Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Quelques exemples d'API :

* L'API **`SecItemCopyMatching`** fournit des informations sur chaque entrée et il y a certains attributs que vous pouvez définir lors de son utilisation :
* **`kSecReturnData`** : Si vrai, il essaiera de déchiffrer les données (définir sur faux pour éviter les pop-ups potentiels)
* **`kSecReturnRef`** : Obtenez également une référence à l'élément de trousseau (définir sur vrai si vous voyez plus tard que vous pouvez déchiffrer sans pop-up)
* **`kSecReturnAttributes`** : Obtenez des métadonnées sur les entrées
* **`kSecMatchLimit`** : Combien de résultats retourner
* **`kSecClass`** : Quel type d'entrée de trousseau

Obtenez les **ACL** de chaque entrée :

* Avec l'API **`SecAccessCopyACLList`**, vous pouvez obtenir l'**ACL pour l'élément de trousseau**, et cela renverra une liste d'ACL (comme `ACLAuhtorizationExportClear` et les autres mentionnés précédemment) où chaque liste a :
* Description
* **Liste des applications de confiance**. Cela pourrait être :
* Une application : /Applications/Slack.app
* Un binaire : /usr/libexec/airportd
* Un groupe : group://AirPort

Exportez les données :

* L'API **`SecKeychainItemCopyContent`** obtient le texte en clair
* L'API **`SecItemExport`** exporte les clés et certificats mais peut nécessiter de définir des mots de passe pour exporter le contenu chiffré

Et voici les **exigences** pour pouvoir **exporter un secret sans invite** :

* Si **1+ applications de confiance** listées :
* Besoin des **autorisations** appropriées (**`Nil`**, ou faire **partie** de la liste autorisée d'applications dans l'autorisation d'accès aux informations secrètes)
* Besoin que la signature de code corresponde à **PartitionID**
* Besoin que la signature de code corresponde à celle d'une **application de confiance** (ou faire partie du bon KeychainAccessGroup)
* Si **toutes les applications sont de confiance** :
* Besoin des **autorisations** appropriées
* Besoin que la signature de code corresponde à **PartitionID**
* Si **pas de PartitionID**, alors cela n'est pas nécessaire

{% hint style="danger" %}
Par conséquent, s'il y a **1 application listée**, vous devez **injecter du code dans cette application**.

Si **apple** est indiqué dans le **partitionID**, vous pourriez y accéder avec **`osascript`** donc tout ce qui fait confiance à toutes les applications avec apple dans le partitionID. **`Python`** pourrait également être utilisé pour cela.
{% endhint %}

### Deux attributs supplémentaires

* **Invisible** : C'est un drapeau booléen pour **cacher** l'entrée de l'application **UI** Keychain
* **Général** : C'est pour stocker des **métadonnées** (donc ce n'est PAS CHIFFRÉ)
* Microsoft stockait en texte clair tous les jetons de rafraîchissement pour accéder à des points de terminaison sensibles.

## Références

* [**#OBTS v5.0 : "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
