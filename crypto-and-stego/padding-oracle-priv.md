# Padding Oracle

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

{% embed url="https://websec.nl/" %}

## CBC - Cipher Block Chaining

CBC modunda **önceki şifreli blok, bir sonraki blokla XOR'lamak için IV olarak kullanılır**:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

CBC'yi deşifre etmek için **ters** **işlemler** yapılır:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

**Şifreleme** **anahtarı** ve bir **IV** kullanmanın gerekli olduğunu unutmayın.

## Mesaj Doldurma

Şifreleme **sabit** **boyut** **bloklarında** gerçekleştirildiğinden, **son** **blokta** uzunluğunu tamamlamak için genellikle **padding** gereklidir.\
Genellikle **PKCS7** kullanılır, bu da bloğu tamamlamak için **gerekli** **byte** **sayısını** **tekrarlayarak** bir padding oluşturur. Örneğin, son blokta 3 byte eksikse, padding `\x03\x03\x03` olacaktır.

**8 byte uzunluğunda 2 blok** ile daha fazla örneğe bakalım:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Son örnekte **son bloğun dolu olduğunu ve sadece padding ile yeni bir bloğun oluşturulduğunu** unutmayın.

## Padding Oracle

Bir uygulama şifreli verileri deşifre ettiğinde, önce verileri deşifre eder; ardından padding'i kaldırır. Padding temizliği sırasında, eğer **geçersiz bir padding tespit edilebilir bir davranış tetiklerse**, bir **padding oracle zafiyeti** vardır. Tespit edilebilir davranış bir **hata**, **sonuç eksikliği** veya **daha yavaş bir yanıt** olabilir.

Bu davranışı tespit ederseniz, **şifreli verileri deşifre edebilir** ve hatta **herhangi bir açık metni şifreleyebilirsiniz**.

### Nasıl istismar edilir

Bu tür bir zafiyeti istismar etmek için [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) kullanabilir veya sadece yapabilirsiniz.
```
sudo apt-get install padbuster
```
Bir sitenin çerezinin zayıf olup olmadığını test etmek için şunları deneyebilirsiniz:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** demek **base64** kullanıldığı anlamına gelir (ancak diğerleri de mevcuttur, yardım menüsüne bakın).

Bu güvenlik açığını **kötüye kullanarak yeni verileri şifreleyebilirsiniz. Örneğin, çerezin içeriği "**_**user=MyUsername**_**" ise, bunu "\_user=administrator\_" olarak değiştirebilir ve uygulama içinde yetkileri artırabilirsiniz. Bunu `paduster` kullanarak -plaintext** parametresini belirterek de yapabilirsiniz:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Eğer site savunmasızsa, `padbuster` otomatik olarak padding hatasının ne zaman meydana geldiğini bulmaya çalışacaktır, ancak hata mesajını **-error** parametresi ile de belirtebilirsiniz.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### Teori

**Özetle**, tüm **farklı padding'leri** oluşturmak için kullanılabilecek doğru değerleri tahmin ederek şifreli verileri çözmeye başlayabilirsiniz. Ardından, padding oracle saldırısı, 1, 2, 3, vb. **padding'leri oluşturan** doğru değeri tahmin ederek son byte'dan başlayarak byte'ları çözmeye başlayacaktır.

![](<../.gitbook/assets/image (561).png>)

Şifrelenmiş ve **E0'dan E15'e** kadar olan byte'ları içeren **2 blok**'a sahip olduğunuzu hayal edin.\
**Son** **blok**'u (**E8**'den **E15**'e) **çözmek** için, tüm blok "blok şifre çözme" işleminden geçerek **I0'dan I15'e** kadar olan **ara byte'ları** oluşturur.\
Sonunda, her ara byte, önceki şifreli byte'larla (E0'dan E7'ye) **XOR**'lanır. Yani:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Artık **`E7`'yi `C15`'i `0x01`** olacak şekilde **değiştirmek** mümkündür; bu da doğru bir padding olacaktır. Bu durumda: `\x01 = I15 ^ E'7`

E'7'yi bulduğunuzda, **I15'i hesaplamak** mümkündür: `I15 = 0x01 ^ E'7`

Bu da **C15'i hesaplamamıza** olanak tanır: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

**C15**'i bildiğinizde, şimdi **C14'ü hesaplamak** mümkündür, ancak bu sefer padding'i `\x02\x02` ile brute-force yaparak.

Bu BF, önceki kadar karmaşıktır çünkü `E''15` değerini 0x02 olarak hesaplamak mümkündür: `E''7 = \x02 ^ I15`, bu nedenle sadece **`E'14`**'ü bulmak gerekir ki bu da **`C14`'ün `0x02`**'ye eşit olmasını sağlar.\
Ardından, C14'ü çözmek için aynı adımları izleyin: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Tüm şifreli metni çözene kadar bu zinciri takip edin.**

### Açığın Tespiti

Bir hesap oluşturun ve bu hesapla giriş yapın.\
Eğer **birçok kez giriş yaparsanız** ve her seferinde **aynı çerezi** alıyorsanız, uygulamada muhtemelen **bir sorun** vardır. **Geri gönderilen çerez her seferinde benzersiz** olmalıdır. Eğer çerez **her zaman** **aynı** ise, muhtemelen her zaman geçerli olacaktır ve onu geçersiz kılmanın bir yolu **olmayacaktır**.

Şimdi, eğer **çerezi değiştirmeye** çalışırsanız, uygulamadan bir **hata** aldığınızı görebilirsiniz.\
Ama eğer padding'i BF yaparsanız (örneğin padbuster kullanarak) farklı bir kullanıcı için geçerli başka bir çerez elde etmeyi başarırsınız. Bu senaryo, padbuster'a karşı yüksek ihtimalle savunmasızdır.

### Referanslar

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
