# Linux Active Directory

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

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

Mashine ya linux inaweza pia kuwepo ndani ya mazingira ya Active Directory.

Mashine ya linux katika AD inaweza kuwa **ikiweka tiketi tofauti za CCACHE ndani ya faili. Tiketi hizi zinaweza kutumika na kutumiwa vibaya kama tiketi nyingine yoyote ya kerberos**. Ili kusoma tiketi hizi utahitaji kuwa mmiliki wa tiketi au **root** ndani ya mashine.

## Enumeration

### AD enumeration kutoka linux

Ikiwa una ufikiaji juu ya AD katika linux (au bash katika Windows) unaweza kujaribu [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) ili kuorodhesha AD.

Unaweza pia kuangalia ukurasa ufuatao kujifunza **njia nyingine za kuorodhesha AD kutoka linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA ni **mbadala** wa chanzo wazi kwa Microsoft Windows **Active Directory**, hasa kwa mazingira ya **Unix**. Inachanganya **LDAP directory** kamili na Kituo cha Usambazaji wa Funguo za MIT **Kerberos** kwa usimamizi unaofanana na Active Directory. Inatumia Mfumo wa **Cheti** wa Dogtag kwa usimamizi wa cheti za CA & RA, inasaidia **uthibitishaji wa hatua nyingi**, ikiwa ni pamoja na kadi za smart. SSSD imeunganishwa kwa michakato ya uthibitishaji wa Unix. Jifunze zaidi kuhusu hiyo katika:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Kucheza na tiketi

### Pass The Ticket

Katika ukurasa huu utapata maeneo tofauti ambapo unaweza **kupata tiketi za kerberos ndani ya mwenyeji wa linux**, katika ukurasa ufuatao unaweza kujifunza jinsi ya kubadilisha muundo wa tiketi hizi za CCache kuwa Kirbi (muundo unaohitajika kutumia katika Windows) na pia jinsi ya kufanya shambulio la PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Urejeleaji wa tiketi za CCACHE kutoka /tmp

Faili za CCACHE ni muundo wa binary kwa **kuhifadhi akidi za Kerberos** ambazo kawaida huhifadhiwa na ruhusa 600 katika `/tmp`. Faili hizi zinaweza kutambulika kwa **muundo wa jina lao, `krb5cc_%{uid}`,** inayohusiana na UID ya mtumiaji. Kwa uthibitishaji wa tiketi, **kigezo cha mazingira `KRB5CCNAME`** kinapaswa kuwekwa kwenye njia ya faili ya tiketi inayotakiwa, kuruhusu urejeleaji wake.

Orodhesha tiketi ya sasa inayotumika kwa uthibitishaji kwa `env | grep KRB5CCNAME`. Muundo ni wa kubebeka na tiketi inaweza **kurudiwa kwa kuweka kigezo cha mazingira** kwa `export KRB5CCNAME=/tmp/ticket.ccache`. Muundo wa jina la tiketi ya Kerberos ni `krb5cc_%{uid}` ambapo uid ni UID ya mtumiaji.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE ticket reuse from keyring

**Tiketi za Kerberos zilizohifadhiwa katika kumbukumbu ya mchakato zinaweza kutolewa**, hasa wakati ulinzi wa ptrace wa mashine umezimwa (`/proc/sys/kernel/yama/ptrace_scope`). Chombo chenye manufaa kwa kusudi hili kinapatikana kwenye [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), ambacho kinasaidia kutoa kwa kuingiza katika vikao na kutupa tiketi kwenye `/tmp`.

Ili kuunda na kutumia chombo hiki, hatua zilizo hapa chini zinafuatwa:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Hii taratibu itajaribu kuingiza katika vikao mbalimbali, ikionyesha mafanikio kwa kuhifadhi tiketi zilizopatikana katika `/tmp` kwa muundo wa majina `__krb_UID.ccache`.


### CCACHE tiketi matumizi tena kutoka SSSD KCM

SSSD inashikilia nakala ya hifadhidata katika njia `/var/lib/sss/secrets/secrets.ldb`. Funguo inayohusiana inahifadhiwa kama faili iliyofichwa katika njia `/var/lib/sss/secrets/.secrets.mkey`. Kwa kawaida, funguo hiyo inaweza kusomwa tu ikiwa una ruhusa za **root**.

Kuita \*\*`SSSDKCMExtractor` \*\* na vigezo --database na --key vitachambua hifadhidata na **kufichua siri**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**kumbukumbu ya akiba ya sifa za Kerberos inaweza kubadilishwa kuwa faili ya Kerberos CCache** inayoweza kupitishwa kwa Mimikatz/Rubeus.

### Urejeo wa tiketi ya CCACHE kutoka kwa keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extract accounts from /etc/krb5.keytab

Funguo za akaunti za huduma, muhimu kwa huduma zinazofanya kazi na ruhusa za mzizi, zimehifadhiwa kwa usalama katika faili za **`/etc/krb5.keytab`**. Funguo hizi, kama nywila za huduma, zinahitaji faragha kali.

Ili kukagua maudhui ya faili la keytab, **`klist`** inaweza kutumika. Chombo hiki kimeundwa kuonyesha maelezo ya funguo, ikiwa ni pamoja na **NT Hash** kwa uthibitishaji wa mtumiaji, hasa wakati aina ya funguo inatambulika kama 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Kwa watumiaji wa Linux, **`KeyTabExtract`** inatoa kazi ya kutoa hash ya RC4 HMAC, ambayo inaweza kutumika kwa ajili ya matumizi tena ya hash ya NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Katika macOS, **`bifrost`** hutumika kama chombo cha uchambuzi wa faili za keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Kwa kutumia taarifa za akaunti na hash zilizovunwa, mawasiliano na seva zinaweza kuanzishwa kwa kutumia zana kama **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## References
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
