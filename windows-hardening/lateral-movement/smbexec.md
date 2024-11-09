# SmbExec/ScExec

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

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Obtenez la perspective d'un hacker sur vos applications web, réseau et cloud

**Trouvez et signalez des vulnérabilités critiques et exploitables ayant un impact commercial réel.** Utilisez nos 20+ outils personnalisés pour cartographier la surface d'attaque, trouver des problèmes de sécurité qui vous permettent d'escalader les privilèges, et utilisez des exploits automatisés pour collecter des preuves essentielles, transformant votre travail acharné en rapports convaincants.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Comment ça fonctionne

**Smbexec** est un outil utilisé pour l'exécution de commandes à distance sur des systèmes Windows, similaire à **Psexec**, mais il évite de placer des fichiers malveillants sur le système cible.

### Points clés sur **SMBExec**

- Il fonctionne en créant un service temporaire (par exemple, "BTOBTO") sur la machine cible pour exécuter des commandes via cmd.exe (%COMSPEC%), sans déposer de binaires.
- Malgré son approche furtive, il génère des journaux d'événements pour chaque commande exécutée, offrant une forme de "shell" non interactif.
- La commande pour se connecter en utilisant **Smbexec** ressemble à ceci :
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Exécution de Commandes Sans Binaires

- **Smbexec** permet l'exécution directe de commandes via les binPaths de service, éliminant le besoin de binaires physiques sur la cible.
- Cette méthode est utile pour exécuter des commandes ponctuelles sur une cible Windows. Par exemple, l'associer au module `web_delivery` de Metasploit permet l'exécution d'un payload Meterpreter inversé ciblé sur PowerShell.
- En créant un service distant sur la machine de l'attaquant avec binPath configuré pour exécuter la commande fournie via cmd.exe, il est possible d'exécuter le payload avec succès, réalisant un rappel et l'exécution du payload avec l'auditeur Metasploit, même si des erreurs de réponse de service se produisent.

### Exemple de Commandes

La création et le démarrage du service peuvent être réalisés avec les commandes suivantes :
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Pour plus de détails, consultez [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Références
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Obtenez la perspective d'un hacker sur vos applications web, votre réseau et le cloud

**Trouvez et signalez des vulnérabilités critiques et exploitables ayant un impact commercial réel.** Utilisez nos 20+ outils personnalisés pour cartographier la surface d'attaque, trouver des problèmes de sécurité qui vous permettent d'escalader les privilèges, et utilisez des exploits automatisés pour collecter des preuves essentielles, transformant votre travail acharné en rapports convaincants.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
