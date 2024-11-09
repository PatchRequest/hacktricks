# SmbExec/ScExec

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

**Pata na ripoti udhaifu muhimu, unaoweza kutumiwa kwa faida, wenye athari halisi za kibiashara.** Tumia zana zetu zaidi ya 20 za kawaida kupanga uso wa shambulio, pata masuala ya usalama yanayokuruhusu kupandisha mamlaka, na tumia matumizi ya moja kwa moja kukusanya ushahidi muhimu, ukigeuza kazi yako ngumu kuwa ripoti za kushawishi.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Jinsi Inavyofanya Kazi

**Smbexec** ni zana inayotumika kwa utekelezaji wa amri kwa mbali kwenye mifumo ya Windows, sawa na **Psexec**, lakini inakwepa kuweka faili zozote za uhalifu kwenye mfumo wa lengo.

### Vidokezo Muhimu Kuhusu **SMBExec**

- Inafanya kazi kwa kuunda huduma ya muda (kwa mfano, "BTOBTO") kwenye mashine ya lengo ili kutekeleza amri kupitia cmd.exe (%COMSPEC%), bila kuacha binaries zozote.
- Licha ya mbinu yake ya siri, inazalisha kumbukumbu za matukio kwa kila amri iliyotekelezwa, ikitoa aina ya "shell" isiyoingiliana.
- Amri ya kuungana kwa kutumia **Smbexec** inaonekana kama hii:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Kutekeleza Amri Bila Binaries

- **Smbexec** inaruhusu utekelezaji wa amri moja kwa moja kupitia binPaths za huduma, ikiondoa hitaji la binaries za kimwili kwenye lengo.
- Njia hii ni muhimu kwa kutekeleza amri za mara moja kwenye lengo la Windows. Kwa mfano, kuunganisha nayo moduli ya `web_delivery` ya Metasploit inaruhusu utekelezaji wa payload ya Meterpreter ya PowerShell.
- Kwa kuunda huduma ya mbali kwenye mashine ya mshambuliaji na binPath iliyowekwa kutekeleza amri iliyotolewa kupitia cmd.exe, inawezekana kutekeleza payload kwa mafanikio, kufikia callback na utekelezaji wa payload na msikilizaji wa Metasploit, hata kama makosa ya majibu ya huduma yanatokea.

### Mfano wa Amri

Kuunda na kuanzisha huduma kunaweza kufanywa kwa amri zifuatazo:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Pata mtazamo wa hacker kuhusu programu zako za wavuti, mtandao, na wingu

**Pata na ripoti kuhusu udhaifu muhimu, unaoweza kutumiwa kwa faida ya biashara halisi.** Tumia zana zetu 20+ za kawaida kupanga uso wa shambulio, pata masuala ya usalama yanayokuruhusu kuongeza mamlaka, na tumia matumizi ya moja kwa moja kukusanya ushahidi muhimu, ukigeuza kazi yako ngumu kuwa ripoti za kushawishi.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
