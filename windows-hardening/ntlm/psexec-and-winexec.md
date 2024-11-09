# PsExec/Winexec/ScExec

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim **alatima** zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Kako funkcionišu

Proces je opisan u koracima ispod, ilustrujući kako se binarni fajlovi servisa manipulišu da bi se postigla daljinska izvršenja na ciljnim mašinama putem SMB:

1. **Kopiranje binarnog fajla servisa na ADMIN$ deljenje putem SMB** se vrši.
2. **Kreiranje servisa na daljinskoj mašini** se vrši upućivanjem na binarni fajl.
3. Servis se **pokreće daljinski**.
4. Po izlasku, servis se **zaustavlja, a binarni fajl se briše**.

### **Proces ručnog izvršavanja PsExec**

Pretpostavljajući da postoji izvršni payload (kreiran sa msfvenom i obfuskovan korišćenjem Veil-a da bi se izbegla antivirusna detekcija), nazvan 'met8888.exe', koji predstavlja meterpreter reverse_http payload, sledeći koraci se preduzimaju:

- **Kopiranje binarnog fajla**: Izvršni fajl se kopira na ADMIN$ deljenje iz komandne linije, iako može biti smešten bilo gde u fajl sistemu da bi ostao skriven.

- **Kreiranje servisa**: Korišćenjem Windows `sc` komande, koja omogućava upit, kreiranje i brisanje Windows servisa na daljinu, kreira se servis nazvan "meterpreter" koji upućuje na otpremljeni binarni fajl.

- **Pokretanje servisa**: Poslednji korak uključuje pokretanje servisa, što će verovatno rezultirati greškom "time-out" zbog toga što binarni fajl nije pravi servisni binarni fajl i ne uspeva da vrati očekivani kod odgovora. Ova greška je beznačajna jer je primarni cilj izvršenje binarnog fajla.

Posmatranje Metasploit slušatelja će otkriti da je sesija uspešno inicirana.

[Saznajte više o `sc` komandi](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Pronađite detaljnije korake na: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Takođe možete koristiti Windows Sysinternals binarni fajl PsExec.exe:**

![](<../../.gitbook/assets/image (165).png>)

Takođe možete koristiti [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) da lako izgradite i **automatizujete radne tokove** pokretane najnaprednijim **alatima** zajednice na svetu.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
