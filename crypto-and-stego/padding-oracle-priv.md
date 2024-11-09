# Padding Oracle

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

## CBC - Cipher Block Chaining

U CBC režimu **prethodni enkriptovani blok se koristi kao IV** za XOR sa sledećim blokom:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Da bi se dekriptovao CBC, **vrše se suprotne** **operacije**:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Primetite kako je potrebno koristiti **ključ za enkripciju** i **IV**.

## Message Padding

Kako se enkripcija vrši u **fiksnim** **veličinama** **blokova**, obično je potrebno **paddovanje** u **poslednjem** **bloku** da bi se završila njegova dužina.\
Obično se koristi **PKCS7**, koji generiše padding **ponavljajući** **broj** **bajtova** **potrebnih** da se **završi** blok. Na primer, ako poslednjem bloku nedostaje 3 bajta, padding će biti `\x03\x03\x03`.

Pogledajmo više primera sa **2 bloka dužine 8 bajtova**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Primetite kako je u poslednjem primeru **poslednji blok bio pun, pa je generisan još jedan samo sa paddingom**.

## Padding Oracle

Kada aplikacija dekriptuje enkriptovane podatke, prvo će dekriptovati podatke; zatim će ukloniti padding. Tokom čišćenja paddinga, ako **nevalidan padding izazove uočljivo ponašanje**, imate **padding oracle ranjivost**. Uočljivo ponašanje može biti **greška**, **nedostatak rezultata**, ili **sporiji odgovor**.

Ako primetite ovo ponašanje, možete **dekriptovati enkriptovane podatke** i čak **enkriptovati bilo koji čist tekst**.

### Kako iskoristiti

Možete koristiti [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) da iskoristite ovu vrstu ranjivosti ili jednostavno uraditi
```
sudo apt-get install padbuster
```
Da biste testirali da li je kolačić sajta ranjiv, možete pokušati:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** znači da se koristi **base64** (ali su dostupni i drugi, proverite meni pomoći).

Takođe možete **iskoristiti ovu ranjivost za enkripciju novih podataka. Na primer, zamislite da je sadržaj kolačića "**_**user=MyUsername**_**", tada ga možete promeniti u "\_user=administrator\_" i eskalirati privilegije unutar aplikacije. Takođe to možete uraditi koristeći `paduster`specifikujući -plaintext** parametar:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Ako je sajt ranjiv, `padbuster` će automatski pokušati da pronađe kada se javlja greška u dodavanju, ali takođe možete naznačiti poruku o grešci koristeći **-error** parametar.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### Teorija

U **kratko**, možete početi dekriptovanje enkriptovanih podataka pogađanjem ispravnih vrednosti koje se mogu koristiti za kreiranje svih **različitih popuna**. Tada će napad na oracle za popunjavanje početi dekriptovanje bajtova od kraja ka početku pogađajući koja će biti ispravna vrednost koja **stvara popunu od 1, 2, 3, itd**.

![](<../.gitbook/assets/image (561).png>)

Zamislite da imate neki enkriptovani tekst koji zauzima **2 bloka** formirana bajtovima od **E0 do E15**.\
Da biste **dekriptovali** **poslednji** **blok** (**E8** do **E15**), ceo blok prolazi kroz "dekripciju blok cifre" generišući **intermedijarne bajtove I0 do I15**.\
Na kraju, svaki intermedijarni bajt se **XOR-uje** sa prethodnim enkriptovanim bajtovima (E0 do E7). Tako:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Sada, moguće je **modifikovati `E7` dok `C15` ne bude `0x01`**, što će takođe biti ispravna popuna. Dakle, u ovom slučaju: `\x01 = I15 ^ E'7`

Dakle, pronalaženjem E'7, **moguće je izračunati I15**: `I15 = 0x01 ^ E'7`

Što nam omogućava da **izračunamo C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Znajući **C15**, sada je moguće **izračunati C14**, ali ovaj put brute-forcing popunu `\x02\x02`.

Ovaj BF je jednako složen kao prethodni jer je moguće izračunati `E''15` čija je vrednost 0x02: `E''7 = \x02 ^ I15` tako da je samo potrebno pronaći **`E'14`** koja generiše **`C14` jednaku `0x02`**.\
Zatim, uradite iste korake da dekriptujete C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Pratite chain dok ne dekriptujete ceo enkriptovani tekst.**

### Otkrivanje ranjivosti

Registrujte se i otvorite nalog i prijavite se sa tim nalogom.\
Ako se **prijavljujete više puta** i uvek dobijate **isti kolačić**, verovatno postoji **nešto** **pogrešno** u aplikaciji. **Kolačić koji se vraća treba da bude jedinstven** svaki put kada se prijavite. Ako je kolačić **uvek** **isti**, verovatno će uvek biti važeći i neće biti načina da se on **nevaži**.

Sada, ako pokušate da **modifikujete** **kolačić**, možete videti da dobijate **grešku** iz aplikacije.\
Ali ako BF popunu (koristeći padbuster na primer) uspete da dobijete drugi kolačić važeći za drugog korisnika. Ovaj scenario je veoma verovatno ranjiv na padbuster.

### Reference

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
