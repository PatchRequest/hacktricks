# Cheat Engine

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), bir oyunun çalıştığı bellek içinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için yararlı bir programdır.\
İndirdiğinizde ve çalıştırdığınızda, aracı nasıl kullanacağınızı gösteren bir **eğitim** ile **karşılaşırsınız**. Aracı nasıl kullanacağınızı öğrenmek istiyorsanız, bunu tamamlamanız şiddetle tavsiye edilir.

## Ne arıyorsunuz?

![](<../../.gitbook/assets/image (762).png>)

Bu araç, bir programın belleğinde **bir değerin** (genellikle bir sayı) **nerede saklandığını bulmak için çok yararlıdır**.\
**Genellikle sayılar** **4bayt** formatında saklanır, ancak bunları **double** veya **float** formatlarında da bulabilirsiniz veya **bir sayıdan farklı bir şey** aramak isteyebilirsiniz. Bu nedenle, neyi **arama** yapmak istediğinizi **seçtiğinizden** emin olmalısınız:

![](<../../.gitbook/assets/image (324).png>)

Ayrıca **farklı** türde **arama** seçenekleri belirtebilirsiniz:

![](<../../.gitbook/assets/image (311).png>)

Belleği tararken **oyunu durdurmak için** kutucuğu işaretleyebilirsiniz:

![](<../../.gitbook/assets/image (1052).png>)

### Kısayollar

_**Düzenle --> Ayarlar --> Kısayollar**_ kısmında, **oyunu durdurmak** gibi farklı amaçlar için farklı **kısayollar** ayarlayabilirsiniz (bu, belleği taramak istediğinizde oldukça kullanışlıdır). Diğer seçenekler de mevcuttur:

![](<../../.gitbook/assets/image (864).png>)

## Değeri Değiştirme

Aradığınız **değerin** nerede olduğunu **bulduğunuzda** (bununla ilgili daha fazla bilgi sonraki adımlarda) onu **değiştirebilirsiniz**; değerine çift tıklayarak ve ardından değerine tekrar çift tıklayarak:

![](<../../.gitbook/assets/image (563).png>)

Ve son olarak, bellekteki değişikliği gerçekleştirmek için **onay kutusunu işaretleyerek**:

![](<../../.gitbook/assets/image (385).png>)

**Bellekteki değişiklik** hemen **uygulanacaktır** (oyun bu değeri tekrar kullanmadığı sürece değer **oyunda güncellenmeyecektir**).

## Değeri Arama

Öyleyse, önemli bir değerin (kullanıcınızın hayatı gibi) olduğunu ve bu değeri bellekte geliştirmek istediğinizi varsayalım.

### Bilinen bir değişim yoluyla

100 değerini aradığınızı varsayalım, bu değeri aramak için bir **tarama** yapıyorsunuz ve birçok eşleşme buluyorsunuz:

![](<../../.gitbook/assets/image (108).png>)

Sonra, **değerin değişmesini** sağlayacak bir şey yapıyorsunuz ve oyunu **durdurup** **bir sonraki taramayı** yapıyorsunuz:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine, **100'den yeni değere** geçen **değerleri** arayacaktır. Tebrikler, aradığınız değerin **adresini buldunuz**, şimdi onu değiştirebilirsiniz.\
Eğer hala birkaç değer varsa, o değeri tekrar değiştirmek için bir şey yapın ve adresleri filtrelemek için bir başka "sonraki tarama" gerçekleştirin.

### Bilinmeyen Değer, bilinen değişim

Değeri **bilmiyorsanız** ama **değişmesini nasıl sağlayacağınızı** biliyorsanız (ve hatta değişim değerini) numaranızı arayabilirsiniz.

Öyleyse, "**Bilinmeyen başlangıç değeri**" türünde bir tarama yaparak başlayın:

![](<../../.gitbook/assets/image (890).png>)

Sonra, değerin değişmesini sağlayın, **değerin nasıl değiştiğini** belirtin (benim durumumda 1 azaldı) ve **bir sonraki taramayı** gerçekleştirin:

![](<../../.gitbook/assets/image (371).png>)

Seçilen şekilde **değiştirilen tüm değerler** size sunulacaktır:

![](<../../.gitbook/assets/image (569).png>)

Değerinizi bulduğunuzda, onu değiştirebilirsiniz.

Birçok **mümkün değişim** olduğunu ve sonuçları filtrelemek için bu **adımları istediğiniz kadar** yapabileceğinizi unutmayın:

![](<../../.gitbook/assets/image (574).png>)

### Rastgele Bellek Adresi - Kodu Bulma

Şimdiye kadar bir değeri saklayan bir adres bulmayı öğrendik, ancak **oyunun farklı çalıştırmalarında bu adresin bellekte farklı yerlerde olma olasılığı yüksektir**. Bu nedenle, bu adresi her zaman nasıl bulacağımızı öğrenelim.

Bahsedilen bazı ipuçlarını kullanarak, mevcut oyunun önemli değeri sakladığı adresi bulun. Sonra (isterseniz oyunu durdurarak) bulunan **adrese sağ tıklayın** ve "**Bu adrese neyin eriştiğini bul**" veya "**Bu adrese neyin yazdığını bul**" seçeneğini seçin:

![](<../../.gitbook/assets/image (1067).png>)

**İlk seçenek**, bu **adresin** hangi **kod parçaları** tarafından **kullanıldığını** bilmek için yararlıdır (bu, oyunun kodunu **nerede değiştirebileceğinizi** bilmek gibi daha fazla şey için yararlıdır).\
**İkinci seçenek** daha **özeldir** ve bu durumda **değerin nereden yazıldığını** bilmekle ilgilendiğimiz için daha faydalı olacaktır.

Bu seçeneklerden birini seçtiğinizde, **hata ayıklayıcı** programa **bağlanacak** ve yeni bir **boş pencere** açılacaktır. Şimdi, **oyunu oynayın** ve **değeri değiştirin** (oyunu yeniden başlatmadan). **Pencere**, **değeri değiştiren** **adreslerle** **doldurulmalıdır**:

![](<../../.gitbook/assets/image (91).png>)

Artık değeri değiştiren adresi bulduğunuza göre, **kodu istediğiniz gibi değiştirebilirsiniz** (Cheat Engine, bunu NOP'lar için hızlı bir şekilde değiştirmenize izin verir):

![](<../../.gitbook/assets/image (1057).png>)

Artık kodu, sayınızı etkilemeyecek şekilde veya her zaman olumlu bir şekilde etkileyecek şekilde değiştirebilirsiniz.

### Rastgele Bellek Adresi - Pointer Bulma

Önceki adımları takip ederek, ilgilendiğiniz değerin nerede olduğunu bulun. Sonra, "**Bu adrese neyin yazdığını bul**" seçeneğini kullanarak bu değeri yazan adresi bulun ve üzerine çift tıklayarak ayrıştırma görünümünü alın:

![](<../../.gitbook/assets/image (1039).png>)

Sonra, **"\[]"** arasındaki hex değerini aramak için yeni bir tarama yapın (bu durumda $edx'in değeri):

![](<../../.gitbook/assets/image (994).png>)

(_Birden fazla görünüyorsa genellikle en küçük adresi almanız gerekir_)\
Artık **ilgilendiğimiz değeri değiştirecek pointer'ı bulduk**.

"**Adresi Manuel Olarak Ekle**" seçeneğine tıklayın:

![](<../../.gitbook/assets/image (990).png>)

Şimdi, "Pointer" onay kutusuna tıklayın ve metin kutusuna bulunan adresi ekleyin (bu senaryoda, önceki resimde bulunan adres "Tutorial-i386.exe"+2426B0 idi):

![](<../../.gitbook/assets/image (392).png>)

(İlk "Adres"in, girdiğiniz pointer adresinden otomatik olarak doldurulduğuna dikkat edin)

Tamam'a tıklayın ve yeni bir pointer oluşturulacaktır:

![](<../../.gitbook/assets/image (308).png>)

Artık, o değeri her değiştirdiğinizde, **değerin bulunduğu bellek adresi farklı olsa bile önemli değeri değiştiriyorsunuz.**

### Kod Enjeksiyonu

Kod enjeksiyonu, hedef işleme bir kod parçası enjekte etme ve ardından kodun yürütülmesini kendi yazdığınız koddan geçirecek şekilde yönlendirme tekniğidir (örneğin, size puan vermek yerine puanları azaltmak).

Öyleyse, oyuncunuzun hayatından 1 çıkaran adresi bulduğunuzu hayal edin:

![](<../../.gitbook/assets/image (203).png>)

**Ayrıştırıcı kodu** almak için "Ayrıştırıcıyı Göster" seçeneğine tıklayın.\
Sonra, **CTRL+a** tuşlarına basarak Otomatik derleme penceresini açın ve _**Şablon --> Kod Enjeksiyonu**_ seçeneğini seçin:

![](<../../.gitbook/assets/image (902).png>)

Değiştirmek istediğiniz **talimatın adresini** doldurun (bu genellikle otomatik olarak doldurulur):

![](<../../.gitbook/assets/image (744).png>)

Bir şablon oluşturulacaktır:

![](<../../.gitbook/assets/image (944).png>)

Öyleyse, yeni assembly kodunuzu "**newmem**" bölümüne ekleyin ve **çalıştırılmasını istemiyorsanız** "**originalcode**" bölümündeki orijinal kodu kaldırın. Bu örnekte, enjekte edilen kod 1 çıkarmak yerine 2 puan ekleyecektir:

![](<../../.gitbook/assets/image (521).png>)

**Uygula'ya tıklayın ve kodunuz programda enjekte edilerek işlevselliğin davranışını değiştirmelidir!**

## **Referanslar**

* **Cheat Engine eğitimi, Cheat Engine ile başlamayı öğrenmek için tamamlayın**

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
