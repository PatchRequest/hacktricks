# Ander Web Tricks

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

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Kry 'n hacker se perspektief op jou web apps, netwerk, en wolk

**Vind en rapporteer kritieke, exploiteerbare kwesbaarhede met werklike besigheidsimpak.** Gebruik ons 20+ pasgemaakte gereedskap om die aanvaloppervlak te karteer, vind sekuriteitskwessies wat jou toelaat om bevoegdhede te verhoog, en gebruik geoutomatiseerde eksploit om noodsaaklike bewyse te versamel, wat jou harde werk in oortuigende verslae omskakel.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

### Gasheer kop

Verskeie kere vertrou die agterkant op die **Gasheer kop** om sekere aksies uit te voer. Byvoorbeeld, dit kan sy waarde gebruik as die **domein om 'n wagwoordherstel te stuur**. So wanneer jy 'n e-pos ontvang met 'n skakel om jou wagwoord te herstel, is die domein wat gebruik word die een wat jy in die Gasheer kop geplaas het. Dan kan jy die wagwoordherstel van ander gebruikers aanvra en die domein verander na een wat deur jou beheer word om hul wagwoordherstelkodes te steel. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Let daarop dat dit moontlik is dat jy nie eers hoef te wag vir die gebruiker om op die hersteld wagwoord skakel te klik om die token te kry nie, aangesien selfs **spamfilters of ander intermediêre toestelle/bots dit mag klik om dit te analiseer**.
{% endhint %}

### Sessie booleans

Soms wanneer jy 'n sekere verifikasie korrek voltooi, sal die agterkant **net 'n boolean met die waarde "True" by 'n sekuriteitsattribuut van jou sessie voeg**. Dan sal 'n ander eindpunt weet of jy daardie toets suksesvol geslaag het.\
As jy egter **die toets slaag** en jou sessie daardie "True" waarde in die sekuriteitsattribuut toegeken word, kan jy probeer om **toegang te verkry tot ander hulpbronne** wat **afhang van dieselfde attribuut** maar waarvoor jy **nie toestemming behoort te hê nie**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Registreer funksionaliteit

Probeer om te registreer as 'n reeds bestaande gebruiker. Probeer ook om ekwivalente karakters te gebruik (punte, baie spasie en Unicode).

### Neem oor e-posse

Registreer 'n e-pos, voordat jy dit bevestig, verander die e-pos, dan, as die nuwe bevestigings e-pos na die eerste geregistreerde e-pos gestuur word, kan jy enige e-pos oorneem. Of as jy die tweede e-pos kan aktiveer wat die eerste een bevestig, kan jy ook enige rekening oorneem.

### Toegang tot interne servicedesk van maatskappye wat atlassian gebruik

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE metode

Ontwikkelaars mag vergeet om verskeie foutopsporing opsies in die produksie-omgewing te deaktiveer. Byvoorbeeld, die HTTP `TRACE` metode is ontwerp vir diagnostiese doeleindes. As dit geaktiveer is, sal die webbediener op versoeke wat die `TRACE` metode gebruik, reageer deur die presiese versoek wat ontvang is in die antwoord te herhaal. Hierdie gedrag is dikwels onskadelik, maar lei soms tot inligtingsontsluiting, soos die naam van interne outentikasie koppe wat aan versoeke deur omgekeerde proxies bygevoeg kan word.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Kry 'n hacker se perspektief op jou web apps, netwerk, en wolk

**Vind en rapporteer kritieke, exploiteerbare kwesbaarhede met werklike besigheidsimpak.** Gebruik ons 20+ pasgemaakte gereedskap om die aanvaloppervlak te karteer, vind sekuriteitskwessies wat jou toelaat om bevoegdhede te verhoog, en gebruik geoutomatiseerde eksploit om noodsaaklike bewyse te versamel, wat jou harde werk in oortuigende verslae omskakel.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

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
