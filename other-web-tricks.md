# Ostali web trikovi

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

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Dobijte perspektivu hakera o vašim web aplikacijama, mreži i cloudu

**Pronađite i prijavite kritične, iskoristive ranjivosti sa stvarnim poslovnim uticajem.** Koristite naših 20+ prilagođenih alata za mapiranje napadačke površine, pronalaženje sigurnosnih problema koji vam omogućavaju da eskalirate privilegije, i koristite automatizovane eksploate za prikupljanje suštinskih dokaza, pretvarajući vaš trud u uverljive izveštaje.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

### Host header

Nekoliko puta back-end veruje **Host header** da izvrši neke radnje. Na primer, može koristiti njegovu vrednost kao **domen za slanje resetovanja lozinke**. Tako kada primite email sa linkom za resetovanje lozinke, domen koji se koristi je onaj koji ste stavili u Host header. Tada možete zatražiti resetovanje lozinke drugih korisnika i promeniti domen na onaj koji kontrolišete kako biste ukrali njihove kodove za resetovanje lozinke. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Imajte na umu da je moguće da ne morate ni da čekate da korisnik klikne na link za resetovanje lozinke da biste dobili token, jer možda čak i **spam filteri ili drugi posrednički uređaji/botovi će kliknuti na njega da ga analiziraju**.
{% endhint %}

### Sesijske boole

Nekada kada ispravno završite neku verifikaciju, back-end će **samo dodati boolean sa vrednošću "True" u sigurnosni atribut vaše sesije**. Tada će druga tačka znati da ste uspešno prošli tu proveru.\
Međutim, ako **prođete proveru** i vašoj sesiji je dodeljena ta "True" vrednost u sigurnosnom atributu, možete pokušati da **pristupite drugim resursima** koji **zavise od istog atributa** ali kojima **ne biste trebali imati dozvolu** za pristup. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funkcionalnost registracije

Pokušajte da se registrujete kao već postojeći korisnik. Pokušajte takođe koristiti ekvivalentne karaktere (tačke, puno razmaka i Unicode).

### Preuzimanje emailova

Registrujte email, pre nego što ga potvrdite promenite email, zatim, ako je novi email za potvrdu poslat na prvi registrovani email, možete preuzeti bilo koji email. Ili ako možete omogućiti drugi email koji potvrđuje prvi, takođe možete preuzeti bilo koji nalog.

### Pristup internom servisnom stolu kompanija koristeći Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE metoda

Programeri mogu zaboraviti da onemoguće razne opcije za debagovanje u produkcionom okruženju. Na primer, HTTP `TRACE` metoda je dizajnirana za dijagnostičke svrhe. Ako je omogućena, web server će odgovoriti na zahteve koji koriste `TRACE` metodu tako što će u odgovoru ponoviti tačan zahtev koji je primljen. Ovo ponašanje je često bezopasno, ali povremeno dovodi do otkrivanja informacija, kao što su imena internih autentifikacionih zaglavlja koja mogu biti dodata zahtevima od strane obrnjenih proksija.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Dobijte perspektivu hakera o vašim web aplikacijama, mreži i cloudu

**Pronađite i prijavite kritične, iskoristive ranjivosti sa stvarnim poslovnim uticajem.** Koristite naših 20+ prilagođenih alata za mapiranje napadačke površine, pronalaženje sigurnosnih problema koji vam omogućavaju da eskalirate privilegije, i koristite automatizovane eksploate za prikupljanje suštinskih dokaza, pretvarajući vaš trud u uverljive izveštaje.

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
