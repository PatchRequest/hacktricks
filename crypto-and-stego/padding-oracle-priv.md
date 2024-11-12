# Padding Oracle

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% embed url="https://websec.nl/" %}

## CBC - Cipher Block Chaining

In CBC mode the **previous encrypted block is used as IV** to XOR with the next block:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

To decrypt CBC the **opposite** **operations** are done:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Notice how it's needed to use an **encryption** **key** and an **IV**.

## Message Padding

As the encryption is performed in **fixed** **size** **blocks**, **padding** is usually needed in the **last** **block** to complete its length.\
Usually **PKCS7** is used, which generates a padding **repeating** the **number** of **bytes** **needed** to **complete** the block. For example, if the last block is missing 3 bytes, the padding will be `\x03\x03\x03`.

Let's look at more examples with a **2 blocks of length 8bytes**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Note how in the last example the **last block was full so another one was generated only with padding**.

## Padding Oracle

When an application decrypts encrypted data, it will first decrypt the data; then it will remove the padding. During the cleanup of the padding, if an **invalid padding triggers a detectable behaviour**, you have a **padding oracle vulnerability**. The detectable behaviour can be an **error**, a **lack of results**, or a **slower response**.

If you detect this behaviour, you can **decrypt the encrypted data** and even **encrypt any cleartext**.

### How to exploit

You could use [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) to exploit this kind of vulnerability or just do
```
sudo apt-get install padbuster
```
Da biste testirali da li je kolačić sajta ranjiv, možete pokušati:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** znači da se koristi **base64** (ali su dostupni i drugi, proverite meni pomoći).

Takođe možete **iskoristiti ovu ranjivost da enkriptujete nove podatke. Na primer, zamislite da je sadržaj kolačića "**_**user=MyUsername**_**", tada ga možete promeniti u "\_user=administrator\_" i eskalirati privilegije unutar aplikacije. Takođe to možete uraditi koristeći `paduster`specifikujući -plaintext** parametar:
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
Da biste **dekriptovali** **poslednji** **blok** (**E8** do **E15**), ceo blok prolazi kroz "dekriptovanje blok šifre" generišući **intermedijarne bajtove I0 do I15**.\
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

**Pratite ovaj lanac dok ne dekriptujete ceo enkriptovani tekst.**

### Otkrivanje ranjivosti

Registrujte se i otvorite nalog i prijavite se sa ovim nalogom.\
Ako se **prijavite više puta** i uvek dobijate **isti kolačić**, verovatno postoji **nešto** **pogrešno** u aplikaciji. **Kolačić koji se vraća treba da bude jedinstven** svaki put kada se prijavite. Ako je kolačić **uvek** **isti**, verovatno će uvek biti važeći i neće biti načina da se on **nevaži**.

Sada, ako pokušate da **modifikujete** **kolačić**, možete videti da dobijate **grešku** iz aplikacije.\
Ali ako BF popunu (koristeći padbuster na primer) uspete da dobijete drugi kolačić važeći za drugog korisnika. Ovaj scenario je veoma verovatno ranjiv na padbuster.

### Reference

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
