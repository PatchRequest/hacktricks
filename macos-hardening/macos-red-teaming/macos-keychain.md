# macOS Anahtar Zinciri

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bizi** **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking ipuçlarını paylaşın,** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Anahtar Zincirleri

* **Kullanıcı Anahtar Zinciri** (`~/Library/Keychains/login.keychain-db`), uygulama şifreleri, internet şifreleri, kullanıcı tarafından oluşturulan sertifikalar, ağ şifreleri ve kullanıcı tarafından oluşturulan açık/özel anahtarlar gibi **kullanıcıya özgü kimlik bilgilerini** saklamak için kullanılır.
* **Sistem Anahtar Zinciri** (`/Library/Keychains/System.keychain`), WiFi şifreleri, sistem kök sertifikaları, sistem özel anahtarları ve sistem uygulama şifreleri gibi **sistem genelinde kimlik bilgilerini** saklar.
* `/System/Library/Keychains/*` içinde sertifikalar gibi diğer bileşenleri bulmak mümkündür.
* **iOS**'ta yalnızca `/private/var/Keychains/` konumunda bir **Anahtar Zinciri** bulunmaktadır. Bu klasör ayrıca `TrustStore`, sertifika otoriteleri (`caissuercache`) ve OSCP girişleri (`ocspache`) için veritabanlarını içerir.
* Uygulamalar, uygulama tanımlayıcılarına dayalı olarak anahtar zincirinde yalnızca özel alanlarına erişimle kısıtlanacaktır.

### Şifre Anahtar Zinciri Erişimi

Bu dosyalar, doğrudan koruma içermemekle birlikte **indirilebilir**, şifrelenmiştir ve **şifresinin çözülmesi için kullanıcının düz metin şifresini** gerektirir. Şifre çözme için [**Chainbreaker**](https://github.com/n0fate/chainbreaker) gibi bir araç kullanılabilir.

## Anahtar Zinciri Girişleri Koruma

### ACL'ler

Anahtar zincirindeki her giriş, çeşitli eylemleri gerçekleştirebilecek kişileri belirleyen **Erişim Kontrol Listeleri (ACL'ler)** ile yönetilmektedir:

* **ACLAuhtorizationExportClear**: Sahip olanın sıfır metin gizliliğini almasına izin verir.
* **ACLAuhtorizationExportWrapped**: Sahip olanın başka bir sağlanan şifre ile şifrelenmiş sıfır metin almasına izin verir.
* **ACLAuhtorizationAny**: Sahip olanın herhangi bir eylemi gerçekleştirmesine izin verir.

ACL'ler, bu eylemleri istem olmadan gerçekleştirebilecek **güvenilir uygulamalar** listesini de içerir. Bu şu olabilir:

* **N`il`** (yetki gerektirmiyor, **herkes güvenilir**)
* **Boş** bir liste (**hiç kimse** güvenilir değil)
* Belirli **uygulamaların** **listesi**.

Ayrıca giriş, **`ACLAuthorizationPartitionID`** anahtarını içerebilir, bu anahtar **teamid, apple** ve **cdhash**'i tanımlamak için kullanılır.

* Eğer **teamid** belirtilmişse, **girişin** değerine **istem olmadan** erişmek için kullanılan uygulamanın **aynı teamid**'ye sahip olması gerekir.
* Eğer **apple** belirtilmişse, uygulamanın **Apple** tarafından **imzalanmış** olması gerekir.
* Eğer **cdhash** belirtilmişse, **uygulama** belirli bir **cdhash**'e sahip olmalıdır.

### Anahtar Zinciri Girişi Oluşturma

Bir **yeni** **giriş** oluşturulduğunda **`Keychain Access.app`** kullanılarak aşağıdaki kurallar geçerlidir:

* Tüm uygulamalar şifreleyebilir.
* **Hiçbir uygulama** dışa aktaramaz/şifre çözemez (kullanıcıyı istemeden).
* Tüm uygulamalar bütünlük kontrolünü görebilir.
* Hiçbir uygulama ACL'leri değiştiremez.
* **partitionID** **`apple`** olarak ayarlanır.

Bir **uygulama anahtar zincirinde bir giriş oluşturduğunda**, kurallar biraz farklıdır:

* Tüm uygulamalar şifreleyebilir.
* Sadece **oluşturan uygulama** (veya açıkça eklenen diğer uygulamalar) dışa aktarabilir/şifre çözebilir (kullanıcıyı istemeden).
* Tüm uygulamalar bütünlük kontrolünü görebilir.
* Hiçbir uygulama ACL'leri değiştiremez.
* **partitionID** **`teamid:[teamID burada]`** olarak ayarlanır.

## Anahtar Zincirine Erişim

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
**Anahtar zinciri numaralandırma ve** **istemci istemi oluşturmayacak** **gizli bilgilerin dökümü** [**LockSmith**](https://github.com/its-a-feature/LockSmith) aracıyla yapılabilir.

Diğer API uç noktaları [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity\_keychain/libsecurity\_keychain-55017/lib/SecKeychain.h.auto.html) kaynak kodunda bulunabilir.
{% endhint %}

**Güvenlik Çerçevesi** kullanarak her anahtar zinciri girişi hakkında **bilgi** listeleyebilir ve alabilirsiniz veya Apple'ın açık kaynaklı cli aracı [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**'yi** de kontrol edebilirsiniz. Bazı API örnekleri:

* API **`SecItemCopyMatching`** her giriş hakkında bilgi verir ve kullanırken ayarlayabileceğiniz bazı özellikler vardır:
* **`kSecReturnData`**: Eğer doğruysa, veriyi şifre çözmeye çalışır (potansiyel açılır pencereleri önlemek için yanlış olarak ayarlayın)
* **`kSecReturnRef`**: Anahtar zinciri öğesine referans da alın (daha sonra açılır pencere olmadan şifre çözebileceğinizi görürseniz doğru olarak ayarlayın)
* **`kSecReturnAttributes`**: Girişler hakkında meta verileri alın
* **`kSecMatchLimit`**: Kaç sonuç döndürüleceği
* **`kSecClass`**: Hangi tür anahtar zinciri girişi

Her girişin **ACL'lerini** alın:

* API **`SecAccessCopyACLList`** ile **anahtar zinciri öğesi için ACL'yi** alabilirsiniz ve bu, her liste için:
* Açıklama
* **Güvenilir Uygulama Listesi**. Bu şunlar olabilir:
* Bir uygulama: /Applications/Slack.app
* Bir ikili: /usr/libexec/airportd
* Bir grup: group://AirPort

Verileri dışa aktarın:

* API **`SecKeychainItemCopyContent`** düz metni alır
* API **`SecItemExport`** anahtarları ve sertifikaları dışa aktarır ancak içeriği şifreli olarak dışa aktarmak için şifre ayarlamanız gerekebilir

Ve bu, **istemci istemi olmadan bir gizli bilgiyi dışa aktarabilmek için** **gereksinimlerdir**:

* Eğer **1+ güvenilir** uygulama listelenmişse:
* Uygun **yetkilendirmelere** ihtiyaç vardır (**`Nil`**, veya gizli bilgiye erişim için yetkilendirme listesinde **yer almak**)
* **PartitionID** ile eşleşen bir kod imzasına ihtiyaç vardır
* Bir **güvenilir uygulama** ile eşleşen bir kod imzasına ihtiyaç vardır (veya doğru KeychainAccessGroup'un üyesi olmalısınız)
* Eğer **tüm uygulamalar güvenilir** ise:
* Uygun **yetkilendirmelere** ihtiyaç vardır
* **PartitionID** ile eşleşen bir kod imzasına ihtiyaç vardır
* Eğer **PartitionID** yoksa, bu gerekli değildir

{% hint style="danger" %}
Bu nedenle, eğer **1 uygulama listelenmişse**, o uygulamaya **kod enjekte etmeniz** gerekir.

Eğer **apple** **partitionID**'de belirtilmişse, **`osascript`** ile erişebilirsiniz, bu nedenle partitionID'de apple olan tüm uygulamalara güvenen herhangi bir şey. Bunun için **`Python`** da kullanılabilir.
{% endhint %}

### İki ek özellik

* **Görünmez**: Bu, girişi **UI** Anahtar Zinciri uygulamasından **gizlemek** için bir boolean bayraktır.
* **Genel**: **Meta verileri** saklamak içindir (yani ŞİFRELİ DEĞİLDİR)
* Microsoft, hassas uç noktaya erişim için tüm yenileme jetonlarını düz metin olarak saklıyordu.

## Referanslar

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
