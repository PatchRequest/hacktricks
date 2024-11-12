# macOS Authorizations DB & Authd

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **Yetkilendirme DB**

`/var/db/auth.db` konumunda bulunan veritabanı, hassas işlemleri gerçekleştirmek için izinleri saklamak amacıyla kullanılan bir veritabanıdır. Bu işlemler tamamen **kullanıcı alanında** gerçekleştirilir ve genellikle belirli bir eylemi gerçekleştirmek için **çağıran istemcinin yetkilendirilip yetkilendirilmediğini** kontrol etmesi gereken **XPC hizmetleri** tarafından kullanılır.

Başlangıçta bu veritabanı, `/System/Library/Security/authorization.plist` içeriğinden oluşturulur. Daha sonra bazı hizmetler, bu veritabanına diğer izinleri eklemek veya mevcut verileri değiştirmek için ekleme yapabilir.

Kurallar, veritabanındaki `rules` tablosunda saklanır ve aşağıdaki sütunları içerir:

* **id**: Her kural için benzersiz bir tanımlayıcı, otomatik olarak artan ve birincil anahtar olarak hizmet eder.
* **name**: Yetkilendirme sisteminde kuralı tanımlamak ve referans vermek için kullanılan kuralın benzersiz adı.
* **type**: Kuralın türünü belirtir, yetkilendirme mantığını tanımlamak için 1 veya 2 değerleriyle sınırlıdır.
* **class**: Kuralı belirli bir sınıfa kategorize eder, pozitif bir tam sayı olmasını sağlar.
* "allow" izin vermek için, "deny" reddetmek için, "user" eğer grup özelliği erişime izin veren bir grup gösteriyorsa, "rule" bir dizide yerine getirilmesi gereken bir kuralı belirtir, "evaluate-mechanisms" ardından `/System/Library/CoreServices/SecurityAgentPlugins/` veya /Library/Security//SecurityAgentPlugins içindeki bir paket adını veya yerleşik olanları içeren bir `mechanisms` dizisi gelir.
* **group**: Grup tabanlı yetkilendirme için kural ile ilişkili kullanıcı grubunu belirtir.
* **kofn**: Toplam sayıdan kaç alt kuralın karşılanması gerektiğini belirleyen "k-of-n" parametresini temsil eder.
* **timeout**: Kural tarafından verilen yetkilendirmenin süresinin dolmadan önceki süreyi tanımlar.
* **flags**: Kuralın davranışını ve özelliklerini değiştiren çeşitli bayrakları içerir.
* **tries**: Güvenliği artırmak için izin verilen yetkilendirme denemelerinin sayısını sınırlar.
* **version**: Kuralın sürümünü sürüm kontrolü ve güncellemeler için takip eder.
* **created**: Kuralın oluşturulduğu zaman damgasını kaydeder, denetim amaçları için.
* **modified**: Kurala yapılan son değişikliğin zaman damgasını saklar.
* **hash**: Kuralın bütünlüğünü sağlamak ve müdahaleyi tespit etmek için kuralın bir hash değerini tutar.
* **identifier**: Kuralın dış referansları için benzersiz bir dize tanımlayıcı, örneğin bir UUID sağlar.
* **requirement**: Kuralın belirli yetkilendirme gereksinimlerini ve mekanizmalarını tanımlayan serileştirilmiş verileri içerir.
* **comment**: Belgelendirme ve açıklık için kural hakkında insan tarafından okunabilir bir açıklama veya yorum sunar.

### Örnek
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Ayrıca [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) adresinde `authenticate-admin-nonshared` ifadesinin anlamını görmek mümkündür:
```json
{
'allow-root' : 'false',
'authenticate-user' : 'true',
'class' : 'user',
'comment' : 'Authenticate as an administrator.',
'group' : 'admin',
'session-owner' : 'false',
'shared' : 'false',
'timeout' : '30',
'tries' : '10000',
'version' : '1'
}
```
## Authd

Bu, istemcilerin hassas eylemleri gerçekleştirmesi için yetkilendirme taleplerini alacak bir daemon'dur. `XPCServices/` klasörü içinde tanımlanmış bir XPC servisi olarak çalışır ve günlüklerini `/var/log/authd.log` dosyasına yazar.

Ayrıca, güvenlik aracını kullanarak birçok `Security.framework` API'sini test etmek mümkündür. Örneğin, `AuthorizationExecuteWithPrivileges` çalıştırarak: `security execute-with-privileges /bin/ls`

Bu, `/usr/libexec/security_authtrampoline /bin/ls`'yi root olarak fork ve exec edecektir; bu da ls'yi root olarak çalıştırmak için bir izin istemi gösterecektir:

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
