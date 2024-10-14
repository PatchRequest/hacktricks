# Investment Terms

## Spot

Bu, ticaret yapmanın en temel yoludur. **Almak veya satmak istediğiniz varlığın miktarını ve fiyatını** belirtebilirsiniz ve o fiyat ulaşıldığında işlem gerçekleştirilir.

Genellikle, işlemi mümkün olan en hızlı şekilde gerçekleştirmek için **mevcut piyasa fiyatını** da kullanabilirsiniz.

**Stop Loss - Limit**: Ayrıca, varlıkların alım veya satım fiyatını belirlerken, ulaşılması durumunda alım veya satım için daha düşük bir fiyat da belirtebilirsiniz (zararları durdurmak için).

## Futures

Bir future, 2 tarafın **belirli bir fiyattan gelecekte bir şey edinme konusunda anlaştığı** bir sözleşmedir. Örneğin, 6 ay içinde 1 bitcoin satmak için 70.000$.

Elbette, 6 ay içinde bitcoin değeri 80.000$ olursa, satıcı taraf para kaybeder ve alıcı taraf kazanır. Eğer 6 ay içinde bitcoin değeri 60.000$ olursa, tersine olur.

Ancak, bu, bir ürün üreten ve maliyetleri karşılayacak bir fiyattan satabileceğinden emin olmak isteyen işletmeler için ilginçtir. Ya da gelecekte bir şey için sabit fiyatlar sağlamak isteyen işletmeler için, hatta daha yüksek olsa bile.

Borsa işlemlerinde genellikle kar elde etmeye çalışmak için kullanılır.

* "Uzun pozisyon" birinin fiyatın artacağına bahse girdiği anlamına gelir.
* "Kısa pozisyon" ise birinin fiyatın düşeceğine bahse girdiği anlamına gelir.

### Hedging With Futures <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Bir fon yöneticisi bazı hisse senetlerinin düşeceğinden korkuyorsa, bitcoinler veya S&P 500 future sözleşmeleri gibi bazı varlıklar üzerinde kısa pozisyon alabilir. Bu, bazı varlıkları satın almak veya bulundurmak ve bunları gelecekte daha yüksek bir fiyattan satma sözleşmesi oluşturmakla benzerlik gösterir.

Eğer fiyat düşerse, fon yöneticisi varlıkları daha yüksek bir fiyattan satacağı için kazanç elde eder. Eğer varlıkların fiyatı artarsa, yönetici bu kazancı elde edemeyecek ama yine de varlıklarını koruyacaktır.

### Perpetual Futures

**Bunlar "futures" olup sonsuz süreyle devam eder** (sonlandırma sözleşme tarihi olmadan). Kripto borsalarında, kripto fiyatlarına dayalı olarak future'lara girip çıkmanın çok yaygın olduğunu görebilirsiniz.

Bu durumlarda kazanç ve kayıplar gerçek zamanlı olabilir; fiyat %1 artarsa %1 kazanırsınız, fiyat %1 düşerse kaybedersiniz.

### Futures with Leverage

**Kaldıraç**, piyasada daha büyük bir pozisyonu daha az para ile kontrol etmenizi sağlar. Temelde, sahip olduğunuzdan çok daha fazla paraya "bahis" yapmanıza olanak tanır, sadece gerçekten sahip olduğunuz parayı riske atarsınız.

Örneğin, BTC/USDT'de 100$ ile 50x kaldıraçla bir future pozisyonu açarsanız, bu, fiyat %1 artarsa, başlangıç yatırımınızın %50'sini (50$) kazanacağınız anlamına gelir. Böylece 150$'ınız olur.\
Ancak, fiyat %1 düşerse, fonlarınızın %50'sini kaybedersiniz (bu durumda 59$). Fiyat %2 düşerse, tüm bahsinizi kaybedersiniz (2x50 = 100%).

Bu nedenle, kaldıraç, bahsettiğiniz para miktarını kontrol etmenizi sağlarken kazanç ve kayıpları artırır.

## Differences Futures & Options

Futures ve opsiyonlar arasındaki ana fark, sözleşmenin alıcı için isteğe bağlı olmasıdır: İsterse sözleşmeyi yerine getirme kararı alabilir (genellikle sadece fayda sağlarsa bunu yapar). Satıcı, alıcı opsiyonu kullanmak isterse satmak zorundadır.\
Ancak, alıcı opsiyonu açmak için satıcıya bir ücret ödeyecektir (bu nedenle, görünüşte daha fazla risk alan satıcı, biraz para kazanmaya başlar).

### 1. **Zorunluluk vs. Hak:**

* **Futures:** Bir future sözleşmesi satın aldığınızda veya sattığınızda, belirli bir tarihte belirli bir fiyattan bir varlık satın alma veya satma konusunda **bağlayıcı bir anlaşmaya** girmiş olursunuz. Hem alıcı hem de satıcı, sözleşmenin sona erdiğinde yükümlüdür (sözleşme o zamandan önce kapatılmadıkça).
* **Opsiyonlar:** Opsiyonlarla, belirli bir tarihte veya öncesinde belirli bir fiyattan bir varlık satın alma (bir **call opsiyonu** durumunda) veya satma (bir **put opsiyonu** durumunda) **hakkına, ancak zorunluluğa sahip** olursunuz. **Alıcı**, opsiyonu kullanma seçeneğine sahiptir, ancak **satıcı**, alıcı opsiyonu kullanmaya karar verirse ticareti yerine getirmekle yükümlüdür.

### 2. **Risk:**

* **Futures:** Hem alıcı hem de satıcı, sözleşmeyi tamamlama yükümlülüğü nedeniyle **sınırsız risk** alır. Risk, sözleşmedeki kararlaştırılan fiyat ile sona erme tarihindeki piyasa fiyatı arasındaki farktır.
* **Opsiyonlar:** Alıcının riski, opsiyonu satın almak için ödenen **primle** sınırlıdır. Piyasa, opsiyon sahibinin lehine hareket etmezse, opsiyonu süresinin dolmasına bırakabilir. Ancak, opsiyonun **satıcısı** (yazarı), piyasa kendilerine karşı önemli ölçüde hareket ederse sınırsız risk taşır.

### 3. **Maliyet:**

* **Futures:** Pozisyonu tutmak için gereken teminat dışında önceden bir maliyet yoktur, çünkü alıcı ve satıcı ticareti tamamlama yükümlülüğündedir.
* **Opsiyonlar:** Alıcı, opsiyonu kullanma hakkı için önceden bir **opsiyon primi** ödemelidir. Bu prim, opsiyonun maliyetidir.

### 4. **Kar Potansiyeli:**

* **Futures:** Kar veya zarar, sona erme tarihindeki piyasa fiyatı ile sözleşmedeki kararlaştırılan fiyat arasındaki farka dayanır.
* **Opsiyonlar:** Alıcı, piyasa, ödenen primden daha fazla bir fiyat hareket ettiğinde kar elde eder. Satıcı, opsiyon kullanılmadığında primi tutarak kar elde eder.
