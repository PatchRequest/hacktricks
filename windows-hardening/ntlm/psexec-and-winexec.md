# PsExec/Winexec/ScExec

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) kujenga na **kujiendesha** kwa urahisi kazi zinazotumiwa na zana za jamii **za kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Jinsi zinavyofanya kazi

Mchakato umeelezwa katika hatua zilizo hapa chini, ukionyesha jinsi binaries za huduma zinavyoshughulikiwa ili kufikia utekelezaji wa mbali kwenye mashine lengwa kupitia SMB:

1. **Kukopi binary ya huduma kwenye ADMIN$ share kupitia SMB** inafanywa.
2. **Kuunda huduma kwenye mashine ya mbali** inafanywa kwa kuelekeza kwenye binary.
3. Huduma inaanzishwa **kwa mbali**.
4. Baada ya kutoka, huduma inasimamishwa, na binary inafutwa.

### **Mchakato wa Kutekeleza PsExec kwa Mikono**

Kukisia kuna payload inayoweza kutekelezwa (iliyoundwa na msfvenom na kufichwa kwa kutumia Veil ili kuepuka kugunduliwa na antivirus), inayoitwa 'met8888.exe', ikiwakilisha payload ya meterpreter reverse_http, hatua zifuatazo zinachukuliwa:

- **Kukopi binary**: Executable inakopiwa kwenye ADMIN$ share kutoka kwa amri ya amri, ingawa inaweza kuwekwa mahali popote kwenye mfumo wa faili ili kubaki kufichwa.

- **Kuunda huduma**: Kutumia amri ya Windows `sc`, ambayo inaruhusu kuuliza, kuunda, na kufuta huduma za Windows kwa mbali, huduma inayoitwa "meterpreter" inaundwa ili kuelekeza kwenye binary iliyopakiwa.

- **Kuanza huduma**: Hatua ya mwisho inahusisha kuanzisha huduma, ambayo itasababisha "time-out" error kwa sababu binary sio binary halisi ya huduma na inashindwa kurudisha msimbo wa majibu unaotarajiwa. Kosa hili halina umuhimu kwani lengo kuu ni utekelezaji wa binary.

Uangalizi wa mlistener wa Metasploit utaonyesha kuwa kikao kimeanzishwa kwa mafanikio.

[Jifunze zaidi kuhusu amri ya `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Pata hatua za kina zaidi katika: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Unaweza pia kutumia binary ya Windows Sysinternals PsExec.exe:**

![](<../../.gitbook/assets/image (165).png>)

Unaweza pia kutumia [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) kujenga na **kujiendesha** kwa urahisi kazi zinazotumiwa na zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
