# Cheat Engine

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje gde su važni podaci sačuvani unutar memorije pokrenute igre i njihovu promenu.\
Kada ga preuzmete i pokrenete, **dobijate** **tutorijal** o tome kako koristiti alat. Ako želite da naučite kako da koristite alat, toplo se preporučuje da ga završite.

## Šta tražite?

![](<../../.gitbook/assets/image (762).png>)

Ovaj alat je veoma koristan za pronalaženje **gde je neka vrednost** (obično broj) **sačuvana u memoriji** programa.\
**Obično se brojevi** čuvaju u **4bajta** formatu, ali ih možete pronaći i u **double** ili **float** formatima, ili možda želite da tražite nešto **drugo osim broja**. Iz tog razloga, morate biti sigurni da **izaberete** ono što želite da **tražite**:

![](<../../.gitbook/assets/image (324).png>)

Takođe možete označiti **različite** tipove **pretraga**:

![](<../../.gitbook/assets/image (311).png>)

Možete takođe označiti opciju da **zaustavite igru dok skenirate memoriju**:

![](<../../.gitbook/assets/image (1052).png>)

### Prečice

U _**Edit --> Settings --> Hotkeys**_ možete postaviti različite **prečice** za različite svrhe kao što su **zaustavljanje** **igre** (što je veoma korisno ako u nekom trenutku želite da skenirate memoriju). Druge opcije su dostupne:

![](<../../.gitbook/assets/image (864).png>)

## Modifikovanje vrednosti

Kada **pronađete** gde je **vrednost** koju tražite (više o ovome u sledećim koracima), možete je **modifikovati** dvostrukim klikom na nju, a zatim dvostrukim klikom na njenu vrednost:

![](<../../.gitbook/assets/image (563).png>)

I konačno **označite ček** da biste izvršili modifikaciju u memoriji:

![](<../../.gitbook/assets/image (385).png>)

**Promena** u **memoriji** će odmah biti **primenjena** (napomena: dok igra ne koristi ovu vrednost ponovo, vrednost **neće biti ažurirana u igri**).

## Traženje vrednosti

Dakle, pretpostavićemo da postoji važna vrednost (kao što je život vašeg korisnika) koju želite da poboljšate, i tražite ovu vrednost u memoriji)

### Kroz poznatu promenu

Pretpostavljajući da tražite vrednost 100, **izvršite skeniranje** tražeći tu vrednost i pronađite mnogo podudaranja:

![](<../../.gitbook/assets/image (108).png>)

Zatim, uradite nešto tako da **vrednost promeni**, i **zaustavite** igru i **izvršite** **sledeće skeniranje**:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine će tražiti **vrednosti** koje su **prešle sa 100 na novu vrednost**. Čestitam, **pronašli ste** **adresu** vrednosti koju ste tražili, sada je možete modifikovati.\
_**Ako još uvek imate nekoliko vrednosti, uradite nešto da ponovo modifikujete tu vrednost, i izvršite još jedno "sledeće skeniranje" da filtrirate adrese.**_

### Nepoznata vrednost, poznata promena

U scenariju kada **ne znate vrednost** ali znate **kako da je promenite** (i čak vrednost promene) možete tražiti svoj broj.

Dakle, počnite tako što ćete izvršiti skeniranje tipa "**Nepoznata početna vrednost**":

![](<../../.gitbook/assets/image (890).png>)

Zatim, promenite vrednost, navedite **kako** se **vrednost** **promenila** (u mom slučaju je smanjena za 1) i izvršite **sledeće skeniranje**:

![](<../../.gitbook/assets/image (371).png>)

Bićete predstavljeni **sve vrednosti koje su modifikovane na odabrani način**:

![](<../../.gitbook/assets/image (569).png>)

Kada pronađete svoju vrednost, možete je modifikovati.

Napomena da postoji **mnogo mogućih promena** i možete raditi ove **korake koliko god želite** da filtrirate rezultate:

![](<../../.gitbook/assets/image (574).png>)

### Nasumična adresa u memoriji - Pronalaženje koda

Do sada smo naučili kako da pronađemo adresu koja čuva vrednost, ali je veoma verovatno da će u **različitim izvršavanjima igre ta adresa biti na različitim mestima u memoriji**. Dakle, hajde da saznamo kako da uvek pronađemo tu adresu.

Koristeći neke od pomenutih trikova, pronađite adresu gde vaša trenutna igra čuva važnu vrednost. Zatim (zaustavljajući igru ako želite) uradite **desni klik** na pronađenu **adresu** i izaberite "**Saznajte šta pristupa ovoj adresi**" ili "**Saznajte šta piše na ovoj adresi**":

![](<../../.gitbook/assets/image (1067).png>)

**Prva opcija** je korisna da saznate koje **delove** **koda** koriste ovu **adresu** (što je korisno za više stvari kao što je **znanje gde možete modifikovati kod** igre).\
**Druga opcija** je više **specifična**, i biće korisnija u ovom slučaju jer nas zanima da saznamo **odakle se ova vrednost piše**.

Kada izaberete jednu od tih opcija, **debugger** će biti **priključen** na program i novi **prazan prozor** će se pojaviti. Sada, **igrajte** **igru** i **modifikujte** tu **vrednost** (bez ponovnog pokretanja igre). **Prozor** bi trebao biti **ispunjen** sa **adresama** koje **modifikuju** **vrednost**:

![](<../../.gitbook/assets/image (91).png>)

Sada kada ste pronašli adresu koja modifikuje vrednost, možete **modifikovati kod po vašoj želji** (Cheat Engine vam omogućava da ga brzo modifikujete za NOPs):

![](<../../.gitbook/assets/image (1057).png>)

Dakle, sada možete modifikovati tako da kod ne utiče na vaš broj, ili će uvek pozitivno uticati.

### Nasumična adresa u memoriji - Pronalaženje pokazivača

Prateći prethodne korake, pronađite gde se vrednost koja vas zanima nalazi. Zatim, koristeći "**Saznajte šta piše na ovoj adresi**" saznajte koja adresa piše ovu vrednost i dvostruko kliknite na nju da biste dobili prikaz disasembly:

![](<../../.gitbook/assets/image (1039).png>)

Zatim, izvršite novo skeniranje **tražeći heksadecimalnu vrednost između "\[]"** (vrednost $edx u ovom slučaju):

![](<../../.gitbook/assets/image (994).png>)

(_Ako se pojavi više njih, obično vam je potrebna najmanja adresa_)\
Sada smo **pronašli pokazivač koji će modifikovati vrednost koja nas zanima**.

Kliknite na "**Dodaj adresu ručno**":

![](<../../.gitbook/assets/image (990).png>)

Sada, kliknite na okvir "Pokazivač" i dodajte pronađenu adresu u tekstualno polje (u ovom scenariju, pronađena adresa na prethodnoj slici je "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (392).png>)

(Napomena kako je prva "Adresa" automatski popunjena iz adrese pokazivača koju ste uneli)

Kliknite na OK i novi pokazivač će biti kreiran:

![](<../../.gitbook/assets/image (308).png>)

Sada, svaki put kada modifikujete tu vrednost, **modifikujete važnu vrednost čak i ako je adresa u memoriji gde se vrednost nalazi drugačija.**

### Injekcija koda

Injekcija koda je tehnika gde injektujete deo koda u ciljni proces, a zatim preusmeravate izvršenje koda da prolazi kroz vaš vlastiti napisani kod (kao što je davanje poena umesto oduzimanja).

Dakle, zamislite da ste pronašli adresu koja oduzima 1 od života vašeg igrača:

![](<../../.gitbook/assets/image (203).png>)

Kliknite na Prikaži disassembler da biste dobili **disasembler kod**.\
Zatim, kliknite **CTRL+a** da pozovete prozor Auto assemble i izaberite _**Template --> Injekcija koda**_

![](<../../.gitbook/assets/image (902).png>)

Popunite **adresu instrukcije koju želite da modifikujete** (ovo se obično automatski popunjava):

![](<../../.gitbook/assets/image (744).png>)

Generisaće se šablon:

![](<../../.gitbook/assets/image (944).png>)

Dakle, umetnite svoj novi assembly kod u sekciju "**newmem**" i uklonite originalni kod iz sekcije "**originalcode**" ako ne želite da se izvršava. U ovom primeru, injektovani kod će dodati 2 poena umesto oduzimanja 1:

![](<../../.gitbook/assets/image (521).png>)

**Kliknite na izvrši i tako dalje i vaš kod bi trebao biti injektovan u program menjajući ponašanje funkcionalnosti!**

## **Reference**

* **Cheat Engine tutorijal, završite ga da biste naučili kako da počnete sa Cheat Engine** 

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
