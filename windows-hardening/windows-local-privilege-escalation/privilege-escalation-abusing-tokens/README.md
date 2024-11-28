# Misbruik van Tokens

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PR's in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Tokens

As jy **nie weet wat Windows Toegangstokens is nie**, lees hierdie bladsy voordat jy voortgaan:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Miskien kan jy bevoegdhede verhoog deur die tokens wat jy reeds het, te misbruik**

### SeImpersonatePrivilege

Dit is 'n bevoegdheid wat deur enige proses gehou word wat die impersonasie (maar nie die skepping) van enige token toelaat, mits 'n handvatsel daarvoor verkry kan word. 'n Bevoorregte token kan van 'n Windows diens (DCOM) verkry word deur dit te dwing om NTLM-verifikasie teen 'n exploit uit te voer, wat dan die uitvoering van 'n proses met SYSTEM bevoegdhede moontlik maak. Hierdie kwesbaarheid kan benut word met verskeie gereedskap, soos [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wat vereis dat winrm gedeaktiveer moet wees), [SweetPotato](https://github.com/CCob/SweetPotato), [EfsPotato](https://github.com/zcgonvh/EfsPotato), [DCOMPotato](https://github.com/zcgonvh/DCOMPotato) en [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Dit is baie soortgelyk aan **SeImpersonatePrivilege**, dit sal die **dieselfde metode** gebruik om 'n bevoorregte token te verkry.\
Dan laat hierdie bevoegdheid **toe om 'n primêre token** aan 'n nuwe/gesuspendeerde proses toe te ken. Met die bevoorregte impersonasie token kan jy 'n primêre token aflei (DuplicateTokenEx).\
Met die token kan jy 'n **nuwe proses** skep met 'CreateProcessAsUser' of 'n proses gesuspend en **die token stel** (in die algemeen kan jy nie die primêre token van 'n lopende proses verander nie).

### SeTcbPrivilege

As jy hierdie token geaktiveer het, kan jy **KERB\_S4U\_LOGON** gebruik om 'n **impersonasie token** vir enige ander gebruiker te verkry sonder om die akrediteer te ken, **voeg 'n arbitrêre groep** (admins) by die token, stel die **integriteitsvlak** van die token op "**medium**", en ken hierdie token toe aan die **huidige draad** (SetThreadToken).

### SeBackupPrivilege

Die stelsel word gedwing om **alle lees toegang** beheer aan enige lêer (beperk tot lees operasies) deur hierdie bevoegdheid te verleen. Dit word gebruik vir **die lees van die wagwoord hashes van plaaslike Administrateur** rekeninge uit die register, waarna gereedskap soos "**psexec**" of "**wmiexec**" met die hash gebruik kan word (Pass-the-Hash tegniek). Hierdie tegniek faal egter onder twee toestande: wanneer die Plaaslike Administrateur rekening gedeaktiveer is, of wanneer 'n beleid in plek is wat administratiewe regte van Plaaslike Administrateurs wat afstand doen, verwyder.\
Jy kan **hierdie bevoegdheid misbruik** met:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* volg **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Of soos verduidelik in die **verhoogde bevoegdhede met Backup Operators** afdeling van:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Toestemming vir **skrywe toegang** tot enige stelsellêer, ongeag die lêer se Toegang Beheer Lys (ACL), word deur hierdie bevoegdheid verskaf. Dit bied talle moontlikhede vir verhoogde bevoegdhede, insluitend die vermoë om **dienste te wysig**, DLL Hijacking uit te voer, en **debuggers** via Beeldlêer Uitvoering Opsies in te stel onder verskeie ander tegnieke.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege is 'n kragtige toestemming, veral nuttig wanneer 'n gebruiker die vermoë het om tokens te impersonate, maar ook in die afwesigheid van SeImpersonatePrivilege. Hierdie vermoë hang af van die vermoë om 'n token te impersonate wat dieselfde gebruiker verteenwoordig en wie se integriteitsvlak nie hoër is as dié van die huidige proses nie.

**Belangrike Punten:**
- **Impersonasie sonder SeImpersonatePrivilege:** Dit is moontlik om SeCreateTokenPrivilege vir EoP te benut deur tokens onder spesifieke toestande te impersonate.
- **Toestande vir Token Impersonasie:** Succesvolle impersonasie vereis dat die teiken token aan dieselfde gebruiker behoort en 'n integriteitsvlak het wat minder of gelyk is aan die integriteitsvlak van die proses wat impersonasie probeer.
- **Skepping en Wysiging van Impersonasie Tokens:** Gebruikers kan 'n impersonasie token skep en dit verbeter deur 'n bevoorregte groep se SID (Veiligheidsidentifiseerder) by te voeg.

### SeLoadDriverPrivilege

Hierdie bevoegdheid laat toe om **toestel bestuurders te laai en te verwyder** met die skepping van 'n register inskrywing met spesifieke waardes vir `ImagePath` en `Type`. Aangesien direkte skrywe toegang tot `HKLM` (HKEY_LOCAL_MACHINE) beperk is, moet `HKCU` (HKEY_CURRENT_USER) eerder gebruik word. Om egter `HKCU` vir die kern herkenbaar te maak vir bestuurder konfigurasie, moet 'n spesifieke pad gevolg word.

Hierdie pad is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, waar `<RID>` die Relatiewe Identifiseerder van die huidige gebruiker is. Binne `HKCU` moet hierdie hele pad geskep word, en twee waardes moet gestel word:
- `ImagePath`, wat die pad na die binêre is wat uitgevoer moet word
- `Type`, met 'n waarde van `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Stappe om te Volg:**
1. Toegang tot `HKCU` eerder as `HKLM` weens beperkte skrywe toegang.
2. Skep die pad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` binne `HKCU`, waar `<RID>` die huidige gebruiker se Relatiewe Identifiseerder verteenwoordig.
3. Stel die `ImagePath` op die binêre se uitvoeringspad.
4. Ken die `Type` toe as `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Meer maniere om hierdie voorreg te misbruik in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dit is soortgelyk aan **SeRestorePrivilege**. Die primêre funksie laat 'n proses toe om **eienaarskap van 'n objek aan te neem**, wat die vereiste vir eksplisiete diskresionêre toegang omseil deur die verskaffing van WRITE_OWNER toegangregte. Die proses behels eers die verkryging van eienaarskap van die beoogde registriesleutel vir skryfdoeleindes, en dan die verandering van die DACL om skryfoperasies moontlik te maak.
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

Hierdie voorreg stel die **ontleding van ander prosesse** in staat, insluitend om in die geheue te lees en te skryf. Verskeie strategieë vir geheue-inspuiting, wat in staat is om die meeste antivirus- en gasheer-inbraakvoorkomingsoplossings te ontwyk, kan met hierdie voorreg toegepas word.

#### Dump geheue

Jy kan [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) van die [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) gebruik om die **geheue van 'n proses** te **vang**. Spesifiek kan dit van toepassing wees op die **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))** proses, wat verantwoordelik is vir die stoor van gebruikersakkrediteer nadat 'n gebruiker suksesvol in 'n stelsel aangemeld het.

Jy kan dan hierdie dump in mimikatz laai om wagwoorde te verkry:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

As jy 'n `NT SYSTEM` shell wil kry, kan jy gebruik maak van:

* ****[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)****
* ****[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Die `SeManageVolumePrivilege` is 'n Windows gebruikersreg wat gebruikers toelaat om skyfvolume te bestuur, insluitend die skep en verwyder daarvan. Alhoewel dit bedoel is vir administrateurs, kan dit, indien aan nie-admin gebruikers toegeken, uitgebuit word vir privilige-escalasie.

Dit is moontlik om hierdie privilige te benut om volumes te manipuleer, wat lei tot volle volume toegang. Die [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) kan gebruik word om volle toegang aan alle gebruikers vir C:\ te gee.

Boonop beskryf die proses uiteengesit in [hierdie Medium-artikel](https://medium.com/@raphaeltzy13/exploiting-semanagevolumeprivilege-with-dll-hijacking-windows-privilege-escalation-1a4f28372d37) die gebruik van DLL-hijacking in samewerking met `SeManageVolumePrivilege` om privilige te eskaleer. Deur 'n payload DLL `C:\Windows\System32\wbem\tzres.dll` te plaas en `systeminfo` aan te roep, word die dll uitgevoer.

## Kontroleer privilige
```
whoami /priv
```
Die **tokens wat as Gedeaktiveer verskyn** kan geaktiveer word, jy kan eintlik _Geaktiveerde_ en _Gedeaktiveerde_ tokens misbruik.

### Aktiveer Alle die tokens

As jy tokens het wat gedeaktiveer is, kan jy die skrip [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) gebruik om al die tokens te aktiveer:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Of die **script** ingebed in hierdie [**plasing**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabel

Volledige token bevoegdhede cheatsheet by [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), opsomming hieronder sal slegs direkte maniere lys om die bevoegdheid te benut om 'n admin-sessie te verkry of sensitiewe lêers te lees.

| Bevoegdheid                | Impak       | Gereedskap              | Uitvoeringspad                                                                                                                                                                                                                                                                                                                                     | Opmerkings                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3de party gereedskap    | _"Dit sal 'n gebruiker toelaat om tokens na te boots en privesc na nt stelsel te gebruik met gereedskap soos potato.exe, rottenpotato.exe en juicypotato.exe"_                                                                                                                                                                              | Dankie [Aurélien Chalot](https://twitter.com/Defte\_) vir die opdatering. Ek sal probeer om dit binnekort in iets meer resep-agtig te herformuleer.                                                                                                                                                                            |
| **`SeBackup`**             | **Dreig**   | _**Ingeboude opdragte**_ | Lees sensitiewe lêers met `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Mag meer interessant wees as jy %WINDIR%\MEMORY.DMP kan lees<br><br>- <code>SeBackupPrivilege</code> (en robocopy) is nie nuttig wanneer dit kom by oop lêers nie.<br><br>- Robocopy vereis beide SeBackup en SeRestore om met /b parameter te werk.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3de party gereedskap    | Skep arbitrêre token insluitend plaaslike admin regte met `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliseer die `lsass.exe` token.                                                                                                                                                                                                                                                                                                                   | Skrip om te vind by [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3de party gereedskap    | <p>1. Laai 'n foutiewe kern bestuurder soos <code>szkg64.sys</code><br>2. Benut die bestuurder kwesbaarheid<br><br>Alternatiewelik kan die bevoegdheid gebruik word om sekuriteitsverwante bestuurders te ontlaai met <code>ftlMC</code> ingeboude opdrag. d.w.z.: <code>fltMC sysmondrv</code></p>                                   | <p>1. Die <code>szkg64</code> kwesbaarheid is gelys as <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Die <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">benuttingskode</a> is geskep deur <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Begin PowerShell/ISE met die SeRestore bevoegdheid teenwoordig.<br>2. Aktiveer die bevoegdheid met <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Hernoem utilman.exe na utilman.old<br>4. Hernoem cmd.exe na utilman.exe<br>5. Vergrendel die konsole en druk Win+U</p> | <p>Die aanval mag deur sommige AV sagteware opgespoor word.</p><p>Alternatiewe metode berus op die vervanging van diens binêre lêers wat in "Program Files" gestoor is met dieselfde bevoegdheid</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Ingeboude opdragte**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Hernoem cmd.exe na utilman.exe<br>4. Vergrendel die konsole en druk Win+U</p>                                                                                                                                       | <p>Die aanval mag deur sommige AV sagteware opgespoor word.</p><p>Alternatiewe metode berus op die vervanging van diens binêre lêers wat in "Program Files" gestoor is met dieselfde bevoegdheid.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3de party gereedskap    | <p>Manipuleer tokens om plaaslike admin regte ingesluit te hê. Mag SeImpersonate vereis.</p><p>Om geverifieer te word.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Verwysing

* Kyk na hierdie tabel wat Windows tokens definieer: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Kyk na [**hierdie papier**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) oor privesc met tokens.

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
