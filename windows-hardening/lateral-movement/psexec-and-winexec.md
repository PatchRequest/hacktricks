# PsExec/Winexec/ScExec

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% embed url="https://websec.nl/" %}

## Kako funkcionišu

Proces je prikazan u koracima ispod, ilustrujući kako se binarni fajlovi servisa manipulišu da bi se postigla daljinska izvršenja na ciljnim mašinama putem SMB:

1. **Kopiranje binarnog fajla servisa na ADMIN$ share preko SMB** se vrši.
2. **Kreiranje servisa na daljinskoj mašini** se vrši upućivanjem na binarni fajl.
3. Servis se **pokreće daljinski**.
4. Po izlasku, servis se **zaustavlja, a binarni fajl se briše**.

### **Proces ručnog izvršavanja PsExec**

Pretpostavljajući da postoji izvršni payload (napravljen sa msfvenom i obfuskovan korišćenjem Veil-a da bi se izbegla detekcija antivirusom), nazvan 'met8888.exe', koji predstavlja meterpreter reverse_http payload, sledeći koraci se preduzimaju:

* **Kopiranje binarnog fajla**: Izvršni fajl se kopira na ADMIN$ share iz komandne linije, iako može biti smešten bilo gde u fajl sistemu da bi ostao skriven.
* **Kreiranje servisa**: Korišćenjem Windows `sc` komande, koja omogućava upit, kreiranje i brisanje Windows servisa na daljinu, kreira se servis nazvan "meterpreter" koji upućuje na otpremljeni binarni fajl.
* **Pokretanje servisa**: Poslednji korak uključuje pokretanje servisa, što će verovatno rezultirati "time-out" greškom zbog toga što binarni fajl nije pravi binarni fajl servisa i ne uspeva da vrati očekivani kod odgovora. Ova greška je beznačajna jer je primarni cilj izvršenje binarnog fajla.

Posmatranje Metasploit slušatelja će otkriti da je sesija uspešno inicirana.

[Learn more about the `sc` command](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Pronađite detaljnije korake na: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Takođe možete koristiti Windows Sysinternals binarni fajl PsExec.exe:**

![](<../../.gitbook/assets/image (928).png>)

Takođe možete koristiti [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
