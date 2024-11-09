# PsExec/Winexec/ScExec

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

## How do they work

Mchakato umeelezwa katika hatua zilizo hapa chini, ukionyesha jinsi binaries za huduma zinavyoshughulikiwa ili kufikia utekelezaji wa mbali kwenye mashine lengwa kupitia SMB:

1. **Nakala ya binary ya huduma kwenye ADMIN$ share kupitia SMB** inafanywa.
2. **Uundaji wa huduma kwenye mashine ya mbali** unafanywa kwa kuelekeza kwenye binary.
3. Huduma inaanzishwa **kwa mbali**.
4. Baada ya kutoka, huduma inasimamishwa, na binary inafutwa.

### **Mchakato wa Kutekeleza PsExec kwa Mikono**

Tukichukulia kuna payload inayoweza kutekelezwa (iliyoundwa na msfvenom na kufichwa kwa kutumia Veil ili kuepuka kugunduliwa na antivirus), inayoitwa 'met8888.exe', ikiwakilisha payload ya meterpreter reverse_http, hatua zifuatazo zinachukuliwa:

* **Nakala ya binary**: Executable inakopwa kwenye ADMIN$ share kutoka kwa amri ya prompt, ingawa inaweza kuwekwa mahali popote kwenye mfumo wa faili ili kubaki kufichwa.
* **Kuunda huduma**: Kutumia amri ya Windows `sc`, ambayo inaruhusu kuuliza, kuunda, na kufuta huduma za Windows kwa mbali, huduma inayoitwa "meterpreter" inaundwa ili kuelekeza kwenye binary iliyopakiwa.
* **Kuanza huduma**: Hatua ya mwisho inahusisha kuanzisha huduma, ambayo itasababisha "time-out" error kwa sababu binary sio binary halisi ya huduma na inashindwa kurudisha msimbo wa majibu unaotarajiwa. Kosa hili halina umuhimu kwani lengo kuu ni utekelezaji wa binary.

Uchunguzi wa mlistener wa Metasploit utaonyesha kuwa kikao kimeanzishwa kwa mafanikio.

[Learn more about the `sc` command](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Find moe detailed steps in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**You could also use the Windows Sysinternals binary PsExec.exe:**

![](<../../.gitbook/assets/image (928).png>)

You could also use [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
