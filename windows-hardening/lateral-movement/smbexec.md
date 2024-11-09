# SmbExec/ScExec

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

#### Kry 'n hacker se perspektief op jou webtoepassings, netwerk, en wolk

**Vind en rapporteer kritieke, exploitable kwesbaarhede met werklike besigheidsimpak.** Gebruik ons 20+ pasgemaakte gereedskap om die aanvaloppervlak te karteer, vind sekuriteitskwessies wat jou toelaat om bevoegdhede te verhoog, en gebruik geoutomatiseerde exploits om noodsaaklike bewyse te versamel, wat jou harde werk in oortuigende verslae omskakel.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Hoe dit Werk

**Smbexec** is 'n hulpmiddel wat gebruik word vir afstandsopdraguitvoering op Windows-stelsels, soortgelyk aan **Psexec**, maar dit vermy om enige kwaadwillige lêers op die teikenstelsel te plaas.

### Sleutelpunte oor **SMBExec**

- Dit werk deur 'n tydelike diens (byvoorbeeld, "BTOBTO") op die teikenmasjien te skep om opdragte via cmd.exe (%COMSPEC%) uit te voer, sonder om enige binêre lêers te laat val.
- Ten spyte van sy stil benadering, genereer dit wel gebeurtenislogboeke vir elke uitgevoerde opdrag, wat 'n vorm van nie-interaktiewe "shell" bied.
- Die opdrag om te verbind met **Smbexec** lyk soos volg:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Uitvoering van Opdragte Sonder Binaries

- **Smbexec** stel direkte opdraguitvoering deur diens binPaths in staat, wat die behoefte aan fisiese binaries op die teiken uitskakel.
- Hierdie metode is nuttig vir die uitvoering van eenmalige opdragte op 'n Windows-teiken. Byvoorbeeld, om dit te kombineer met Metasploit se `web_delivery` module stel dit in staat om 'n PowerShell-gefokusde omgekeerde Meterpreter payload uit te voer.
- Deur 'n afstanddiens op die aanvaller se masjien te skep met binPath ingestel om die verskafde opdrag deur cmd.exe uit te voer, is dit moontlik om die payload suksesvol uit te voer, wat terugroep en payload-uitvoering met die Metasploit-luisteraar bereik, selfs al gebeur diensresponsfoute.

### Opdragte Voorbeeld

Die skep en begin van die diens kan met die volgende opdragte gedoen word:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Kry 'n hacker se perspektief op jou webtoepassings, netwerk en wolk

**Vind en rapporteer kritieke, exploiteerbare kwesbaarhede met werklike besigheidsimpak.** Gebruik ons 20+ pasgemaakte gereedskap om die aanvaloppervlak te karteer, vind sekuriteitskwessies wat jou toelaat om bevoegdhede te verhoog, en gebruik geoutomatiseerde eksploit om noodsaaklike bewyse te versamel, wat jou harde werk in oortuigende verslae omskep.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
