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

In modalità CBC, il **blocco crittografato precedente viene utilizzato come IV** per XORare con il blocco successivo:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Per decrittografare CBC, vengono eseguite le **operazioni** **opposte**:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Nota come sia necessario utilizzare una **chiave di crittografia** e un **IV**.

## Message Padding

Poiché la crittografia viene eseguita in **blocchi** di **dimensioni** **fisse**, è solitamente necessario un **padding** nell'**ultimo** **blocco** per completarne la lunghezza.\
Di solito si utilizza **PKCS7**, che genera un padding **ripetendo** il **numero** di **byte** **necessari** per **completare** il blocco. Ad esempio, se l'ultimo blocco manca di 3 byte, il padding sarà `\x03\x03\x03`.

Esaminiamo altri esempi con **2 blocchi di lunghezza 8byte**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Nota come nell'ultimo esempio l'**ultimo blocco fosse pieno, quindi ne è stato generato un altro solo con padding**.

## Padding Oracle

Quando un'applicazione decrittografa dati crittografati, prima decrittografa i dati; poi rimuove il padding. Durante la pulizia del padding, se un **padding non valido attiva un comportamento rilevabile**, hai una **vulnerabilità di padding oracle**. Il comportamento rilevabile può essere un **errore**, una **mancanza di risultati** o una **risposta più lenta**.

Se rilevi questo comportamento, puoi **decrittografare i dati crittografati** e persino **crittografare qualsiasi testo in chiaro**.

### How to exploit

Potresti usare [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) per sfruttare questo tipo di vulnerabilità o semplicemente fare
```
sudo apt-get install padbuster
```
Per testare se il cookie di un sito è vulnerabile, potresti provare:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** significa che **base64** è utilizzato (ma sono disponibili altri, controlla il menu di aiuto).

Potresti anche **sfruttare questa vulnerabilità per crittografare nuovi dati. Ad esempio, immagina che il contenuto del cookie sia "**_**user=MyUsername**_**", quindi potresti cambiarlo in "\_user=administrator\_" ed elevare i privilegi all'interno dell'applicazione. Potresti anche farlo usando `paduster` specificando il parametro -plaintext**:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Se il sito è vulnerabile, `padbuster` proverà automaticamente a trovare quando si verifica l'errore di padding, ma puoi anche indicare il messaggio di errore utilizzando il parametro **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### La teoria

In **sintesi**, puoi iniziare a decrittare i dati crittografati indovinando i valori corretti che possono essere utilizzati per creare tutti i **diversi padding**. Poi, l'attacco padding oracle inizierà a decrittare i byte dalla fine all'inizio indovinando quale sarà il valore corretto che **crea un padding di 1, 2, 3, ecc**.

![](<../.gitbook/assets/image (561).png>)

Immagina di avere del testo crittografato che occupa **2 blocchi** formati dai byte da **E0 a E15**.\
Per **decrittare** l'**ultimo** **blocco** (**E8** a **E15**), l'intero blocco passa attraverso la "decrittazione del blocco" generando i **byte intermedi I0 a I15**.\
Infine, ogni byte intermedio è **XORato** con i byte crittografati precedenti (E0 a E7). Quindi:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Ora, è possibile **modificare `E7` fino a quando `C15` è `0x01`**, che sarà anche un padding corretto. Quindi, in questo caso: `\x01 = I15 ^ E'7`

Quindi, trovando E'7, è **possibile calcolare I15**: `I15 = 0x01 ^ E'7`

Il che ci consente di **calcolare C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Sapendo **C15**, ora è possibile **calcolare C14**, ma questa volta forzando il padding `\x02\x02`.

Questo BF è complesso quanto il precedente poiché è possibile calcolare il `E''15` il cui valore è 0x02: `E''7 = \x02 ^ I15` quindi è solo necessario trovare il **`E'14`** che genera un **`C14` uguale a `0x02`**.\
Poi, eseguire gli stessi passaggi per decrittare C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Segui questa catena fino a decrittare l'intero testo crittografato.**

### Rilevamento della vulnerabilità

Registrati e accedi con questo account.\
Se **accedi molte volte** e ottieni sempre la **stessa cookie**, probabilmente c'è **qualcosa** **sbagliato** nell'applicazione. La **cookie restituita dovrebbe essere unica** ogni volta che accedi. Se la cookie è **sempre** la **stessa**, probabilmente sarà sempre valida e non ci **sarà modo di invalidarla**.

Ora, se provi a **modificare** la **cookie**, puoi vedere che ricevi un **errore** dall'applicazione.\
Ma se forzi il padding (usando padbuster per esempio) riesci a ottenere un'altra cookie valida per un utente diverso. Questo scenario è altamente probabile che sia vulnerabile a padbuster.

### Riferimenti

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
