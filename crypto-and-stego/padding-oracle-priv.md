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

No modo CBC, o **bloco criptografado anterior é usado como IV** para XOR com o próximo bloco:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Para descriptografar o CBC, as **operações** **opostas** são realizadas:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Note como é necessário usar uma **chave de criptografia** e um **IV**.

## Message Padding

Como a criptografia é realizada em **blocos** de **tamanho fixo**, o **padding** geralmente é necessário no **último** **bloco** para completar seu comprimento.\
Normalmente, utiliza-se **PKCS7**, que gera um padding **repetindo** o **número** de **bytes** **necessários** para **completar** o bloco. Por exemplo, se o último bloco estiver faltando 3 bytes, o padding será `\x03\x03\x03`.

Vamos ver mais exemplos com **2 blocos de comprimento 8bytes**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Note como no último exemplo o **último bloco estava cheio, então outro foi gerado apenas com padding**.

## Padding Oracle

Quando uma aplicação descriptografa dados criptografados, ela primeiro descriptografa os dados; então remove o padding. Durante a limpeza do padding, se um **padding inválido acionar um comportamento detectável**, você tem uma **vulnerabilidade de padding oracle**. O comportamento detectável pode ser um **erro**, uma **falta de resultados** ou uma **resposta mais lenta**.

Se você detectar esse comportamento, pode **descriptografar os dados criptografados** e até mesmo **criptografar qualquer texto claro**.

### How to exploit

Você poderia usar [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) para explorar esse tipo de vulnerabilidade ou apenas fazer
```
sudo apt-get install padbuster
```
Para testar se o cookie de um site é vulnerável, você poderia tentar:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** significa que **base64** é usado (mas outros estão disponíveis, verifique o menu de ajuda).

Você também poderia **abusar dessa vulnerabilidade para criptografar novos dados. Por exemplo, imagine que o conteúdo do cookie é "**_**user=MyUsername**_**", então você pode alterá-lo para "\_user=administrator\_" e escalar privilégios dentro da aplicação. Você também poderia fazer isso usando `paduster` especificando o parâmetro -plaintext**:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Se o site for vulnerável, `padbuster` tentará automaticamente descobrir quando o erro de padding ocorre, mas você também pode indicar a mensagem de erro usando o parâmetro **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### A teoria

Em **resumo**, você pode começar a descriptografar os dados criptografados adivinhando os valores corretos que podem ser usados para criar todos os **diferentes paddings**. Então, o ataque de padding oracle começará a descriptografar bytes do final para o início, adivinhando qual será o valor correto que **cria um padding de 1, 2, 3, etc**.

![](<../.gitbook/assets/image (561).png>)

Imagine que você tem algum texto criptografado que ocupa **2 blocos** formados pelos bytes de **E0 a E15**.\
Para **descriptografar** o **último** **bloco** (**E8** a **E15**), todo o bloco passa pela "descriptografia de bloco" gerando os **bytes intermediários I0 a I15**.\
Finalmente, cada byte intermediário é **XORed** com os bytes criptografados anteriores (E0 a E7). Então:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Agora, é possível **modificar `E7` até que `C15` seja `0x01`**, o que também será um padding correto. Então, neste caso: `\x01 = I15 ^ E'7`

Assim, encontrando E'7, é **possível calcular I15**: `I15 = 0x01 ^ E'7`

O que nos permite **calcular C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Sabendo **C15**, agora é possível **calcular C14**, mas desta vez forçando o padding `\x02\x02`.

Esse BF é tão complexo quanto o anterior, pois é possível calcular o `E''15` cujo valor é 0x02: `E''7 = \x02 ^ I15`, então só é necessário encontrar o **`E'14`** que gera um **`C14` igual a `0x02`**.\
Então, faça os mesmos passos para descriptografar C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Siga essa cadeia até que você descriptografe todo o texto criptografado.**

### Detecção da vulnerabilidade

Registre e crie uma conta e faça login com essa conta.\
Se você **fizer login muitas vezes** e sempre receber o **mesmo cookie**, provavelmente há **algo** **errado** na aplicação. O **cookie enviado de volta deve ser único** cada vez que você faz login. Se o cookie é **sempre** o **mesmo**, provavelmente sempre será válido e não **haverá como invalidá-lo**.

Agora, se você tentar **modificar** o **cookie**, pode ver que recebe um **erro** da aplicação.\
Mas se você BF o padding (usando padbuster, por exemplo), consegue obter outro cookie válido para um usuário diferente. Esse cenário é altamente provável de ser vulnerável ao padbuster.

### Referências

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
