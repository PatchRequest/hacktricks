# macOS Security & Privilege Escalation

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server kuwasiliana na hackers wenye uzoefu na wawindaji wa bug bounty!

**Hacking Insights**\
Shiriki na maudhui yanayoangazia msisimko na changamoto za hacking

**Real-Time Hack News**\
Baki na habari za kisasa kuhusu ulimwengu wa hacking kupitia habari na maarifa ya wakati halisi

**Latest Announcements**\
Baki na taarifa kuhusu bug bounties mpya zinazozinduliwa na masasisho muhimu ya jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na uanze kushirikiana na hackers bora leo!

## Basic MacOS

Ikiwa hujafahamu macOS, unapaswa kuanza kujifunza misingi ya macOS:

* Faili maalum za macOS **na ruhusa:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Watumiaji wa kawaida wa macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **muundo** wa k**ernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Huduma za kawaida za macOS n**etwork na protokali**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Ili kupakua `tar.gz` badilisha URL kama [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) kuwa [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Katika kampuni **sistimu za macOS** zina uwezekano mkubwa kuwa **zinadhibitiwa na MDM**. Kwa hivyo, kutoka mtazamo wa mshambuliaji ni muhimu kujua **jinsi hiyo inavyofanya kazi**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Kukagua, Kurekebisha na Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS Security Protections

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Attack Surface

### File Permissions

Ikiwa **mchakato unaotendewa kama root unaandika** faili ambayo inaweza kudhibitiwa na mtumiaji, mtumiaji anaweza kuitumia vibaya ili **kuinua ruhusa**.\
Hii inaweza kutokea katika hali zifuatazo:

* Faili iliyotumika tayari iliumbwa na mtumiaji (inamilikiwa na mtumiaji)
* Faili iliyotumika inaweza kuandikwa na mtumiaji kwa sababu ya kundi
* Faili iliyotumika iko ndani ya directory inayomilikiwa na mtumiaji (mtumiaji anaweza kuunda faili hiyo)
* Faili iliyotumika iko ndani ya directory inayomilikiwa na root lakini mtumiaji ana ufikiaji wa kuandika juu yake kwa sababu ya kundi (mtumiaji anaweza kuunda faili hiyo)

Kuwa na uwezo wa **kuunda faili** ambayo itatumika na **root**, inamruhusu mtumiaji **kunufaika na maudhui yake** au hata kuunda **symlinks/hardlinks** kuielekeza mahali pengine.

Kwa aina hii ya udhaifu usisahau **kuangalia waandishi wa `.pkg` walio hatarini**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### File Extension & URL scheme app handlers

Programu za ajabu zilizosajiliwa na nyongeza za faili zinaweza kutumika vibaya na programu tofauti zinaweza kuandikishwa kufungua protokali maalum

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Privilege Escalation

Katika macOS **programu na binaries zinaweza kuwa na ruhusa** za kufikia folda au mipangilio inayowafanya kuwa na nguvu zaidi kuliko wengine.

Kwa hivyo, mshambuliaji anayetaka kufanikiwa kuathiri mashine ya macOS atahitaji **kuinua ruhusa zake za TCC** (au hata **kupita SIP**, kulingana na mahitaji yake).

Ruhusa hizi kwa kawaida hutolewa kwa njia ya **entitlements** ambayo programu imesainiwa nayo, au programu inaweza kuomba baadhi ya ufikiaji na baada ya **mtumiaji kuidhinisha** wanaweza kupatikana katika **maktaba za TCC**. Njia nyingine mchakato unaweza kupata ruhusa hizi ni kwa kuwa **mtoto wa mchakato** wenye hizo **ruhusa** kwani kwa kawaida **zinarithiwa**.

Fuata viungo hivi kupata njia tofauti za [**kuinua ruhusa katika TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**kupita TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) na jinsi katika siku za nyuma [**SIP imepita**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Traditional Privilege Escalation

Bila shaka kutoka mtazamo wa timu nyekundu unapaswa pia kuwa na hamu ya kuinua hadi root. Angalia chapisho lifuatalo kwa vidokezo vingine:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## macOS Compliance

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos_security)

## References

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server kuwasiliana na hackers wenye uzoefu na wawindaji wa bug bounty!

**Hacking Insights**\
Shiriki na maudhui yanayoangazia msisimko na changamoto za hacking

**Real-Time Hack News**\
Baki na habari za kisasa kuhusu ulimwengu wa hacking kupitia habari na maarifa ya wakati halisi

**Latest Announcements**\
Baki na taarifa kuhusu bug bounties mpya zinazozinduliwa na masasisho muhimu ya jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na uanze kushirikiana na hackers bora leo!

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
