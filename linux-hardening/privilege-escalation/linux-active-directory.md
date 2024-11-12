# Linux Active Directory

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

{% embed url="https://websec.nl/" %}

'n Linux masjien kan ook teenwoordig wees binne 'n Active Directory omgewing.

'n Linux masjien in 'n AD mag **verskillende CCACHE kaartjies binne lêers stoor. Hierdie kaartjies kan gebruik en misbruik word soos enige ander kerberos kaartjie**. Om hierdie kaartjies te lees, moet jy die gebruiker-eienaar van die kaartjie wees of **root** binne die masjien.

## Enumerasie

### AD enumerasie vanaf linux

As jy toegang het oor 'n AD in linux (of bash in Windows) kan jy probeer [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) om die AD te enumerate.

Jy kan ook die volgende bladsy nagaan om te leer **ander maniere om AD vanaf linux te enumerate**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA is 'n oopbron **alternatief** vir Microsoft Windows **Active Directory**, hoofsaaklik vir **Unix** omgewings. Dit kombineer 'n volledige **LDAP gids** met 'n MIT **Kerberos** Sleutelverspreidingsentrum vir bestuur soortgelyk aan Active Directory. Dit gebruik die Dogtag **Sertifikaatstelsel** vir CA & RA sertifikaatbestuur, en ondersteun **multi-faktor** verifikasie, insluitend slimkaarte. SSSD is geïntegreer vir Unix verifikasieprosesse. Leer meer daaroor in:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Speel met kaartjies

### Pass The Ticket

Op hierdie bladsy gaan jy verskillende plekke vind waar jy **kerberos kaartjies binne 'n linux gasheer kan vind**, op die volgende bladsy kan jy leer hoe om hierdie CCache kaartjie formate na Kirbi (die formaat wat jy in Windows moet gebruik) te transformeer en ook hoe om 'n PTT aanval uit te voer:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### CCACHE kaartjie hergebruik vanaf /tmp

CCACHE lêers is binêre formate vir **storing Kerberos akrediteer** en word tipies gestoor met 600 toestemmings in `/tmp`. Hierdie lêers kan geïdentifiseer word deur hul **naamformaat, `krb5cc_%{uid}`,** wat ooreenstem met die gebruiker se UID. Vir verifikasie van die verifikasieticket, moet die **omgewing veranderlike `KRB5CCNAME`** op die pad van die gewenste kaartjie lêer gestel word, wat hergebruik moontlik maak.

Lys die huidige kaartjie wat vir verifikasie gebruik word met `env | grep KRB5CCNAME`. Die formaat is draagbaar en die kaartjie kan **hergebruik word deur die omgewing veranderlike** met `export KRB5CCNAME=/tmp/ticket.ccache` te stel. Kerberos kaartjie naamformaat is `krb5cc_%{uid}` waar uid die gebruiker se UID is.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE kaart hergebruik vanaf sleutelring

**Kerberos-kaarte wat in 'n proses se geheue gestoor is, kan onttrek word**, veral wanneer die masjien se ptrace-beskerming gedeaktiveer is (`/proc/sys/kernel/yama/ptrace_scope`). 'n Nuttige hulpmiddel vir hierdie doel is te vind by [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), wat die onttrekking vergemaklik deur in sessies in te spuit en kaarte in `/tmp` te dump.

Om hierdie hulpmiddel te konfigureer en te gebruik, word die onderstaande stappe gevolg:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Hierdie prosedure sal probeer om in verskeie sessies in te spuit, wat sukses aandui deur onttrokken kaartjies in `/tmp` te stoor met 'n naamkonvensie van `__krb_UID.ccache`.

### CCACHE kaartjie hergebruik van SSSD KCM

SSSD hou 'n kopie van die databasis by die pad `/var/lib/sss/secrets/secrets.ldb`. Die ooreenstemmende sleutel word as 'n verborge lêer by die pad `/var/lib/sss/secrets/.secrets.mkey` gestoor. Standaard is die sleutel slegs leesbaar as jy **root** regte het.

Die **`SSSDKCMExtractor`** met die --database en --key parameters sal die databasis ontleed en **die geheime** dekripteer.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Die **akkrediteringskas Kerberos blob kan in 'n bruikbare Kerberos CCache** lêer omgeskakel word wat aan Mimikatz/Rubeus oorgedra kan word.

### CCACHE kaartjie hergebruik vanaf keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Trek rekeninge uit /etc/krb5.keytab

Diensrekening sleutels, wat noodsaaklik is vir dienste wat met wortelprivileges werk, word veilig gestoor in **`/etc/krb5.keytab`** lêers. Hierdie sleutels, soortgelyk aan wagwoorde vir dienste, vereis streng vertroulikheid.

Om die inhoud van die keytab-lêer te ondersoek, kan **`klist`** gebruik word. Die hulpmiddel is ontwerp om sleuteldetails te vertoon, insluitend die **NT Hash** vir gebruikersverifikasie, veral wanneer die sleuteltipe as 23 geïdentifiseer word.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Vir Linux gebruikers bied **`KeyTabExtract`** funksionaliteit om die RC4 HMAC-has te onttrek, wat benut kan word vir NTLM-has hergebruik.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Op macOS dien **`bifrost`** as 'n hulpmiddel vir sleuteltabelfilaanalyse.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Met die onttrokken rekening- en hash-inligting kan verbindings met bedieners gevestig word met behulp van gereedskap soos **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Verwysings

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
