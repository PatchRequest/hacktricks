# Abusing Tokens

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

## Tokens

Si vous **ne savez pas ce que sont les Windows Access Tokens**, lisez cette page avant de continuer :

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Peut-être pourriez-vous être en mesure d'escalader les privilèges en abusant des tokens que vous avez déjà**

### SeImpersonatePrivilege

C'est un privilège détenu par tout processus qui permet l'imitation (mais pas la création) de tout token, à condition qu'un handle puisse être obtenu. Un token privilégié peut être acquis à partir d'un service Windows (DCOM) en l'incitant à effectuer une authentification NTLM contre un exploit, permettant ensuite l'exécution d'un processus avec des privilèges SYSTEM. Cette vulnérabilité peut être exploitée à l'aide de divers outils, tels que [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (qui nécessite que winrm soit désactivé), [SweetPotato](https://github.com/CCob/SweetPotato), [EfsPotato](https://github.com/zcgonvh/EfsPotato), [DCOMPotato](https://github.com/zcgonvh/DCOMPotato) et [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Il est très similaire à **SeImpersonatePrivilege**, il utilisera la **même méthode** pour obtenir un token privilégié.\
Ensuite, ce privilège permet **d'assigner un token principal** à un nouveau processus/suspendu. Avec le token d'imitation privilégié, vous pouvez dériver un token principal (DuplicateTokenEx).\
Avec le token, vous pouvez créer un **nouveau processus** avec 'CreateProcessAsUser' ou créer un processus suspendu et **définir le token** (en général, vous ne pouvez pas modifier le token principal d'un processus en cours d'exécution).

### SeTcbPrivilege

Si vous avez activé ce token, vous pouvez utiliser **KERB\_S4U\_LOGON** pour obtenir un **token d'imitation** pour tout autre utilisateur sans connaître les identifiants, **ajouter un groupe arbitraire** (administrateurs) au token, définir le **niveau d'intégrité** du token à "**moyen**", et assigner ce token au **fil d'exécution actuel** (SetThreadToken).

### SeBackupPrivilege

Le système est amené à **accorder tous les droits de lecture** à tout fichier (limité aux opérations de lecture) par ce privilège. Il est utilisé pour **lire les hachages de mot de passe des comptes Administrateur locaux** à partir du registre, après quoi, des outils comme "**psexec**" ou "**wmiexec**" peuvent être utilisés avec le hachage (technique Pass-the-Hash). Cependant, cette technique échoue sous deux conditions : lorsque le compte Administrateur local est désactivé, ou lorsqu'une politique est en place qui retire les droits administratifs des Administrateurs locaux se connectant à distance.\
Vous pouvez **abuser de ce privilège** avec :

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* suivant **IppSec** dans [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Ou comme expliqué dans la section **escalade des privilèges avec les opérateurs de sauvegarde** de :

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

La permission pour **l'accès en écriture** à tout fichier système, indépendamment de la liste de contrôle d'accès (ACL) du fichier, est fournie par ce privilège. Il ouvre de nombreuses possibilités d'escalade, y compris la capacité de **modifier des services**, effectuer du DLL Hijacking, et définir des **débogueurs** via les options d'exécution de fichiers d'image parmi diverses autres techniques.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege est une permission puissante, particulièrement utile lorsqu'un utilisateur possède la capacité d'imiter des tokens, mais aussi en l'absence de SeImpersonatePrivilege. Cette capacité repose sur la possibilité d'imiter un token qui représente le même utilisateur et dont le niveau d'intégrité ne dépasse pas celui du processus actuel.

**Points clés :**
- **Imitation sans SeImpersonatePrivilege :** Il est possible de tirer parti de SeCreateTokenPrivilege pour EoP en imitant des tokens dans des conditions spécifiques.
- **Conditions pour l'imitation de token :** Une imitation réussie nécessite que le token cible appartienne au même utilisateur et ait un niveau d'intégrité inférieur ou égal à celui du processus tentant l'imitation.
- **Création et modification de tokens d'imitation :** Les utilisateurs peuvent créer un token d'imitation et l'améliorer en ajoutant un SID (Identifiant de sécurité) d'un groupe privilégié.

### SeLoadDriverPrivilege

Ce privilège permet de **charger et décharger des pilotes de périphériques** en créant une entrée de registre avec des valeurs spécifiques pour `ImagePath` et `Type`. Étant donné que l'accès en écriture direct à `HKLM` (HKEY_LOCAL_MACHINE) est restreint, `HKCU` (HKEY_CURRENT_USER) doit être utilisé à la place. Cependant, pour rendre `HKCU` reconnaissable par le noyau pour la configuration des pilotes, un chemin spécifique doit être suivi.

Ce chemin est `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, où `<RID>` est l'Identifiant Relatif de l'utilisateur actuel. À l'intérieur de `HKCU`, ce chemin entier doit être créé, et deux valeurs doivent être définies :
- `ImagePath`, qui est le chemin vers le binaire à exécuter
- `Type`, avec une valeur de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Étapes à suivre :**
1. Accéder à `HKCU` au lieu de `HKLM` en raison de l'accès en écriture restreint.
2. Créer le chemin `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dans `HKCU`, où `<RID>` représente l'Identifiant Relatif de l'utilisateur actuel.
3. Définir `ImagePath` sur le chemin d'exécution du binaire.
4. Assigner `Type` comme `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Plus de façons d'abuser de ce privilège dans [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ceci est similaire à **SeRestorePrivilege**. Sa fonction principale permet à un processus de **prendre possession d'un objet**, contournant l'exigence d'un accès discrétionnaire explicite grâce à la fourniture de droits d'accès WRITE_OWNER. Le processus consiste d'abord à sécuriser la possession de la clé de registre prévue à des fins d'écriture, puis à modifier le DACL pour permettre les opérations d'écriture.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Ce privilège permet de **déboguer d'autres processus**, y compris de lire et d'écrire dans la mémoire. Diverses stratégies d'injection de mémoire, capables d'échapper à la plupart des solutions antivirus et de prévention des intrusions hôtes, peuvent être employées avec ce privilège.

#### Dump mémoire

Vous pouvez utiliser [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de la [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) pour **capturer la mémoire d'un processus**. Plus précisément, cela peut s'appliquer au processus **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, qui est responsable du stockage des informations d'identification des utilisateurs une fois qu'un utilisateur s'est connecté avec succès à un système.

Vous pouvez ensuite charger ce dump dans mimikatz pour obtenir des mots de passe :
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Si vous voulez obtenir un shell `NT SYSTEM`, vous pouvez utiliser :

* ****[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)****
* ****[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1 (Script Powershell)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Le `SeManageVolumePrivilege` est un droit utilisateur Windows qui permet aux utilisateurs de gérer les volumes de disque, y compris de les créer et de les supprimer. Bien qu'il soit destiné aux administrateurs, s'il est accordé à des utilisateurs non administrateurs, il peut être exploité pour une élévation de privilèges.

Il est possible de tirer parti de ce privilège pour manipuler les volumes, ce qui conduit à un accès complet au volume. L'[SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) peut être utilisé pour donner un accès complet à tous les utilisateurs pour C:\

De plus, le processus décrit dans [cet article Medium](https://medium.com/@raphaeltzy13/exploiting-semanagevolumeprivilege-with-dll-hijacking-windows-privilege-escalation-1a4f28372d37) explique comment utiliser le détournement de DLL en conjonction avec `SeManageVolumePrivilege` pour élever les privilèges. En plaçant une DLL de charge utile `C:\Windows\System32\wbem\tzres.dll` et en appelant `systeminfo`, la dll est exécutée.

## Vérifier les privilèges
```
whoami /priv
```
Les **tokens qui apparaissent comme Désactivés** peuvent être activés, vous pouvez en fait abuser des tokens _Activés_ et _Désactivés_.

### Activer tous les tokens

Si vous avez des tokens désactivés, vous pouvez utiliser le script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) pour activer tous les tokens :
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ou le **script** intégré dans ce [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

La feuille de triche complète des privilèges de jeton est disponible à [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), le résumé ci-dessous ne listera que les moyens directs d'exploiter le privilège pour obtenir une session admin ou lire des fichiers sensibles.

| Privilège                  | Impact      | Outil                   | Chemin d'exécution                                                                                                                                                                                                                                                                                                                                     | Remarques                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Outil tiers             | _"Cela permettrait à un utilisateur d'imiter des jetons et de privesc au système nt en utilisant des outils tels que potato.exe, rottenpotato.exe et juicypotato.exe"_                                                                                                                                                                          | Merci à [Aurélien Chalot](https://twitter.com/Defte\_) pour la mise à jour. J'essaierai de reformuler cela en quelque chose de plus ressemblant à une recette bientôt.                                                                                                                                                          |
| **`SeBackup`**             | **Menace**  | _**Commandes intégrées**_ | Lire des fichiers sensibles avec `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Peut être plus intéressant si vous pouvez lire %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (et robocopy) n'est pas utile lorsqu'il s'agit de fichiers ouverts.<br><br>- Robocopy nécessite à la fois SeBackup et SeRestore pour fonctionner avec le paramètre /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Outil tiers             | Créer un jeton arbitraire incluant des droits d'administrateur local avec `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliquer le jeton `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Script à trouver sur [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Outil tiers             | <p>1. Charger un pilote de noyau bogué tel que <code>szkg64.sys</code><br>2. Exploiter la vulnérabilité du pilote<br><br>Alternativement, le privilège peut être utilisé pour décharger des pilotes liés à la sécurité avec la commande intégrée <code>ftlMC</code>. c'est-à-dire : <code>fltMC sysmondrv</code></p>                                                                           | <p>1. La vulnérabilité <code>szkg64</code> est répertoriée comme <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Le <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">code d'exploitation</a> a été créé par <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Lancer PowerShell/ISE avec le privilège SeRestore présent.<br>2. Activer le privilège avec <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renommer utilman.exe en utilman.old<br>4. Renommer cmd.exe en utilman.exe<br>5. Verrouiller la console et appuyer sur Win+U</p> | <p>L'attaque peut être détectée par certains logiciels antivirus.</p><p>La méthode alternative repose sur le remplacement des binaires de service stockés dans "Program Files" en utilisant le même privilège</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Commandes intégrées**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renommer cmd.exe en utilman.exe<br>4. Verrouiller la console et appuyer sur Win+U</p>                                                                                                                                       | <p>L'attaque peut être détectée par certains logiciels antivirus.</p><p>La méthode alternative repose sur le remplacement des binaires de service stockés dans "Program Files" en utilisant le même privilège.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Outil tiers             | <p>Manipuler des jetons pour inclure des droits d'administrateur local. Peut nécessiter SeImpersonate.</p><p>À vérifier.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Référence

* Jetez un œil à ce tableau définissant les jetons Windows : [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Jetez un œil à [**ce document**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) sur le privesc avec des jetons.

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
