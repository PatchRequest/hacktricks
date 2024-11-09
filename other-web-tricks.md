# Other Web Tricks

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

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Pata mtazamo wa hacker kuhusu programu zako za wavuti, mtandao, na wingu

**Pata na ripoti mapungufu makubwa, yanayoweza kutumiwa kwa faida na athari halisi za kibiashara.** Tumia zana zetu zaidi ya 20 za kawaida kupanga uso wa shambulio, pata masuala ya usalama yanayokuruhusu kupandisha mamlaka, na tumia matumizi ya kiotomatiki kukusanya ushahidi muhimu, ukigeuza kazi yako ngumu kuwa ripoti za kushawishi.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

### Kichwa cha mwenyeji

Mara kadhaa nyuma ya pazia inategemea **Kichwa cha mwenyeji** kufanya baadhi ya vitendo. Kwa mfano, inaweza kutumia thamani yake kama **domain ya kutuma upya nenosiri**. Hivyo unapopokea barua pepe yenye kiungo cha kutengeneza upya nenosiri lako, domain inayotumika ni ile uliyoweka katika Kichwa cha mwenyeji. Kisha, unaweza kuomba upya nenosiri wa watumiaji wengine na kubadilisha domain kuwa moja inayodhibitiwa na wewe ili kuiba nambari zao za upya nenosiri. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Kumbuka kwamba inawezekana usihitaji hata kusubiri mtumiaji abonyeze kiungo cha kutengeneza upya nenosiri ili kupata tokeni, kwani labda hata **filamu za spam au vifaa/vibot vingine vya kati vitabonyeza ili kuchambua**.
{% endhint %}

### Boolean za kikao

Wakati mwingine unapokamilisha uthibitisho fulani kwa usahihi, nyuma ya pazia itachukua **kuongeza boolean tu yenye thamani "True" kwa sifa ya usalama ya kikao chako**. Kisha, mwisho tofauti utajua ikiwa umepita hiyo ukaguzi kwa mafanikio.\
Hata hivyo, ikiwa **umepita ukaguzi** na kikao chako kinapewa thamani hiyo "True" katika sifa ya usalama, unaweza kujaribu **kufikia rasilimali nyingine** ambazo **zinategemea sifa hiyo hiyo** lakini ambazo **hupaswi kuwa na ruhusa** za kufikia. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Kazi ya kujiandikisha

Jaribu kujiandikisha kama mtumiaji ambaye tayari yupo. Jaribu pia kutumia wahusika sawa (madoadoa, nafasi nyingi na Unicode).

### Kuchukua barua pepe

Jiandikishe barua pepe, kabla ya kuithibitisha badilisha barua pepe, kisha, ikiwa barua pepe mpya ya uthibitisho itatumwa kwa barua pepe ya kwanza iliyosajiliwa, unaweza kuchukua barua pepe yoyote. Au ikiwa unaweza kuwezesha barua pepe ya pili kuthibitisha ya kwanza, unaweza pia kuchukua akaunti yoyote.

### Fikia huduma za ndani za kampuni zinazotumia atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Njia ya TRACE

Wakandarasi wanaweza kusahau kuzima chaguzi mbalimbali za ufuatiliaji katika mazingira ya uzalishaji. Kwa mfano, njia ya HTTP `TRACE` imeundwa kwa madhumuni ya uchunguzi. Ikiwa imewezeshwa, seva ya wavuti itajibu maombi yanayotumia njia ya `TRACE` kwa kurudisha katika jibu ombi halisi lililopokelewa. Tabia hii mara nyingi haina madhara, lakini wakati mwingine husababisha kufichuliwa kwa habari, kama vile jina la vichwa vya uthibitishaji vya ndani ambavyo vinaweza kuongezwa kwa maombi na proxies za kinyume.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Pata mtazamo wa hacker kuhusu programu zako za wavuti, mtandao, na wingu

**Pata na ripoti mapungufu makubwa, yanayoweza kutumiwa kwa faida na athari halisi za kibiashara.** Tumia zana zetu zaidi ya 20 za kawaida kupanga uso wa shambulio, pata masuala ya usalama yanayokuruhusu kupandisha mamlaka, na tumia matumizi ya kiotomatiki kukusanya ushahidi muhimu, ukigeuza kazi yako ngumu kuwa ripoti za kushawishi.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

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
