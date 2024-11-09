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

#### Get a hacker's perspective on your web apps, network, and cloud

**Pronađite i prijavite kritične, iskoristive ranjivosti sa stvarnim poslovnim uticajem.** Koristite naših 20+ prilagođenih alata za mapiranje napadačke površine, pronalaženje sigurnosnih problema koji vam omogućavaju da eskalirate privilegije, i koristite automatizovane eksploate za prikupljanje suštinskih dokaza, pretvarajući vaš trud u uverljive izveštaje.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## How it Works

**Smbexec** je alat koji se koristi za daljinsko izvršavanje komandi na Windows sistemima, sličan **Psexec**, ali izbegava postavljanje bilo kojih zlonamernih datoteka na ciljni sistem.

### Key Points about **SMBExec**

- Deluje tako što kreira privremenu uslugu (na primer, "BTOBTO") na ciljnim mašinama za izvršavanje komandi putem cmd.exe (%COMSPEC%), bez ispuštanja bilo kakvih binarnih datoteka.
- I pored svog diskretnog pristupa, generiše dnevničke zapise za svaku izvršenu komandu, nudeći oblik neinteraktivnog "shell-a".
- Komanda za povezivanje koristeći **Smbexec** izgleda ovako:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Izvršavanje Komandi Bez Binarnih Fajlova

- **Smbexec** omogućava direktno izvršavanje komandi kroz binPaths servisa, eliminišući potrebu za fizičkim binarnim fajlovima na meti.
- Ova metoda je korisna za izvršavanje jednokratnih komandi na Windows meti. Na primer, kombinovanjem sa Metasploit-ovim `web_delivery` modulom omogućava izvršavanje PowerShell-targetiranog obrnuto Meterpreter payload-a.
- Kreiranjem udaljenog servisa na napadačevoj mašini sa binPath postavljenim da izvrši pruženu komandu kroz cmd.exe, moguće je uspešno izvršiti payload, postizajući povratne informacije i izvršavanje payload-a sa Metasploit slušačem, čak i ako dođe do grešaka u odgovoru servisa.

### Primer Komandi

Kreiranje i pokretanje servisa može se ostvariti sledećim komandama:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Dobijte perspektivu hakera na vaše web aplikacije, mrežu i oblak

**Pronađite i prijavite kritične, iskoristive ranjivosti sa stvarnim poslovnim uticajem.** Koristite naših 20+ prilagođenih alata za mapiranje napada, pronalaženje sigurnosnih problema koji vam omogućavaju da eskalirate privilegije, i koristite automatizovane eksploate za prikupljanje suštinskih dokaza, pretvarajući vaš trud u uverljive izveštaje.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

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
