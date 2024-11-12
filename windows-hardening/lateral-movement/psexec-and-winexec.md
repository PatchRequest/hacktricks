# PsExec/Winexec/ScExec

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PR's in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% embed url="https://websec.nl/" %}

## Hoe werk hulle

Die proses word in die onderstaande stappe uiteengesit, wat illustreer hoe diens binaire gemanipuleer word om afstandsuitvoering op 'n teiken masjien via SMB te bereik:

1. **Kopieer van 'n diens binaire na die ADMIN$ deel oor SMB** word uitgevoer.
2. **Skep van 'n diens op die afstandsmasjien** word gedoen deur na die binaire te verwys.
3. Die diens word **afstandsbegin**.
4. By uitgang, word die diens **gestop, en die binaire word verwyder**.

### **Proses van Handmatige Uitvoering van PsExec**

Aneem daar is 'n uitvoerbare payload (gecreëer met msfvenom en obfuskeer met Veil om antivirus opsporing te ontduik), genaamd 'met8888.exe', wat 'n meterpreter reverse\_http payload verteenwoordig, die volgende stappe word geneem:

* **Kopieer die binaire**: Die uitvoerbare word na die ADMIN$ deel gekopieer vanaf 'n opdragprompt, alhoewel dit enige plek op die lêerstelsel geplaas kan word om verborge te bly.
* **Skep 'n diens**: Deur die Windows `sc` opdrag te gebruik, wat toelaat om Windows dienste afstands te vra, te skep en te verwyder, word 'n diens genaamd "meterpreter" geskep om na die opgelaaide binaire te verwys.
* **Begin die diens**: Die finale stap behels die begin van die diens, wat waarskynlik 'n "time-out" fout sal veroorsaak weens die binaire nie 'n werklike diens binaire is nie en nie die verwagte responskode teruggee nie. Hierdie fout is onbelangrik aangesien die primêre doel die uitvoering van die binaire is.

Waarneming van die Metasploit luisteraar sal onthul dat die sessie suksesvol geinitieer is.

[Leer meer oor die `sc` opdrag](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Vind meer gedetailleerde stappe in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Jy kan ook die Windows Sysinternals binaire PsExec.exe gebruik:**

![](<../../.gitbook/assets/image (928).png>)

Jy kan ook [**SharpLateral**](https://github.com/mertdas/SharpLateral) gebruik:

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

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
