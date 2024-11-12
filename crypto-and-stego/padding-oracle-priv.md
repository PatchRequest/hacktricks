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
Ili kujaribu kama cookie ya tovuti ina udhaifu unaweza kujaribu:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** inamaanisha kwamba **base64** inatumika (lakini zingine zinapatikana, angalia menyu ya msaada).

Unaweza pia **kutumia udhaifu huu kubadilisha data mpya. Kwa mfano, fikiria kwamba maudhui ya cookie ni "**_**user=MyUsername**_**", kisha unaweza kubadilisha kuwa "\_user=administrator\_" na kuongeza mamlaka ndani ya programu. Unaweza pia kufanya hivyo kwa kutumia `paduster`ukitaja -plaintext** parameter:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Ikiwa tovuti ina udhaifu `padbuster` itajaribu moja kwa moja kubaini wakati kosa la padding linapotokea, lakini unaweza pia kuashiria ujumbe wa kosa hilo ukitumia **-error** parameter.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### Nadharia

Kwa **muhtasari**, unaweza kuanza kufungua data iliyosimbwa kwa kubashiri thamani sahihi ambazo zinaweza kutumika kuunda **paddings tofauti**. Kisha, shambulio la padding oracle litaanza kufungua byte kutoka mwisho hadi mwanzo kwa kubashiri ni ipi itakuwa thamani sahihi inayounda padding ya **1, 2, 3, n.k.**.

![](<../.gitbook/assets/image (561).png>)

Fikiria una maandiko yaliyosimbwa yanayochukua **blocks 2** yaliyoundwa na byte kutoka **E0 hadi E15**.\
Ili **kufungua** **block** ya **mwisho** (**E8** hadi **E15**), block nzima inapita kupitia "block cipher decryption" ikizalisha **byte za kati I0 hadi I15**.\
Hatimaye, kila byte ya kati inafanywa **XOR** na byte zilizopita zilizofichwa (E0 hadi E7). Hivyo:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Sasa, inawezekana **kubadilisha `E7` hadi `C15` iwe `0x01`**, ambayo pia itakuwa padding sahihi. Hivyo, katika kesi hii: `\x01 = I15 ^ E'7`

Hivyo, kupata E'7, inawezekana **kuhesabu I15**: `I15 = 0x01 ^ E'7`

Ambayo inaturuhusu **kuhesabu C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Kujua **C15**, sasa inawezekana **kuhesabu C14**, lakini wakati huu kwa kubashiri padding `\x02\x02`.

Hii BF ni ngumu kama ile ya awali kwani inawezekana kuhesabu `E''15` ambayo thamani yake ni 0x02: `E''7 = \x02 ^ I15` hivyo inahitajika tu kupata **`E'14`** inayozalisha **`C14` inayolingana na `0x02`**.\
Kisha, fanya hatua hizo hizo kufungua C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Fuata mnyororo huu hadi ufungue maandiko yote yaliyosimbwa.**

### Ugunduzi wa udhaifu

Jisajili na ujiandikishe na akaunti hii.\
Ikiwa unafanya **kuingia mara nyingi** na kila wakati unapata **keki ile ile**, kuna uwezekano wa **kitu** **kibaya** katika programu. **Keki inayotumwa nyuma inapaswa kuwa ya kipekee** kila wakati unapoingia. Ikiwa keki ni **daima** ile **ile**, kuna uwezekano itakuwa daima halali na hakuna **njia ya kuifuta**.

Sasa, ikiwa unajaribu **kubadilisha** **keki**, unaweza kuona unapata **kosa** kutoka kwa programu.\
Lakini ikiwa unafanya BF padding (ukitumia padbuster kwa mfano) unafanikiwa kupata keki nyingine halali kwa mtumiaji tofauti. Hali hii ina uwezekano mkubwa wa kuwa na udhaifu kwa padbuster.

### Marejeleo

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki hila za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
