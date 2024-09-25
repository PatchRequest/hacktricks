# macOS Kernel Extensions

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

## Basic Information

Rozszerzenia jądra (Kexts) to **pakiety** z rozszerzeniem **`.kext`**, które są **ładowane bezpośrednio do przestrzeni jądra macOS**, zapewniając dodatkową funkcjonalność głównemu systemowi operacyjnemu.

### Requirements

Oczywiście, jest to tak potężne, że **załadowanie rozszerzenia jądra** jest **skomplikowane**. Oto **wymagania**, które musi spełniać rozszerzenie jądra, aby mogło być załadowane:

* Podczas **wejścia w tryb odzyskiwania**, rozszerzenia jądra **muszą być dozwolone** do załadowania:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Rozszerzenie jądra musi być **podpisane certyfikatem podpisywania kodu jądra**, który może być **przyznany tylko przez Apple**. Kto dokładnie przeanalizuje firmę i powody, dla których jest to potrzebne.
* Rozszerzenie jądra musi być również **notaryzowane**, Apple będzie mogło sprawdzić je pod kątem złośliwego oprogramowania.
* Następnie, użytkownik **root** jest tym, który może **załadować rozszerzenie jądra**, a pliki wewnątrz pakietu muszą **należeć do roota**.
* Podczas procesu ładowania pakiet musi być przygotowany w **chronionej lokalizacji nie-root**: `/Library/StagedExtensions` (wymaga przyznania `com.apple.rootless.storage.KernelExtensionManagement`).
* Na koniec, podczas próby załadowania, użytkownik [**otrzyma prośbę o potwierdzenie**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) i, jeśli zostanie zaakceptowana, komputer musi być **uruchomiony ponownie**, aby go załadować.

### Loading process

W Catalina wyglądało to tak: Interesujące jest to, że proces **weryfikacji** zachodzi w **userland**. Jednak tylko aplikacje z przyznaniem **`com.apple.private.security.kext-management`** mogą **zażądać od jądra załadowania rozszerzenia**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **rozpoczyna** proces **weryfikacji** ładowania rozszerzenia
* Będzie komunikować się z **`kextd`** za pomocą **usługi Mach**.
2. **`kextd`** sprawdzi kilka rzeczy, takich jak **podpis**
* Będzie komunikować się z **`syspolicyd`**, aby **sprawdzić**, czy rozszerzenie może być **załadowane**.
3. **`syspolicyd`** **poprosi** **użytkownika**, jeśli rozszerzenie nie zostało wcześniej załadowane.
* **`syspolicyd`** przekaże wynik do **`kextd`**
4. **`kextd`** w końcu będzie mógł **powiedzieć jądru, aby załadowało** rozszerzenie

Jeśli **`kextd`** nie jest dostępny, **`kextutil`** może przeprowadzić te same kontrole.

### Enumeration (loaded kexts)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

{% hint style="danger" %}
Chociaż rozszerzenia jądra powinny znajdować się w `/System/Library/Extensions/`, jeśli przejdziesz do tego folderu, **nie znajdziesz żadnego pliku binarnego**. Dzieje się tak z powodu **kernelcache** i aby odwrócić jeden `.kext`, musisz znaleźć sposób na jego uzyskanie.
{% endhint %}

**Kernelcache** to **wstępnie skompilowana i wstępnie połączona wersja jądra XNU**, wraz z niezbędnymi **sterownikami** i **rozszerzeniami jądra**. Jest przechowywana w **skompresowanym** formacie i dekompresowana do pamięci podczas procesu uruchamiania. Kernelcache ułatwia **szybszy czas uruchamiania**, mając gotową do uruchomienia wersję jądra i kluczowych sterowników, co zmniejsza czas i zasoby, które w przeciwnym razie byłyby wydawane na dynamiczne ładowanie i łączenie tych komponentów w czasie uruchamiania.

### Lokalny Kernelcache

W iOS znajduje się w **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, w macOS możesz go znaleźć za pomocą: **`find / -name "kernelcache" 2>/dev/null`** \
W moim przypadku w macOS znalazłem go w:

* `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Format pliku IMG4 to format kontenerowy używany przez Apple w urządzeniach iOS i macOS do bezpiecznego **przechowywania i weryfikowania komponentów oprogramowania układowego** (takich jak **kernelcache**). Format IMG4 zawiera nagłówek i kilka tagów, które kapsułkują różne fragmenty danych, w tym rzeczywisty ładunek (tak jak jądro lub bootloader), podpis oraz zestaw właściwości manifestu. Format wspiera weryfikację kryptograficzną, pozwalając urządzeniu potwierdzić autentyczność i integralność komponentu oprogramowania układowego przed jego wykonaniem.

Zwykle składa się z następujących komponentów:

* **Payload (IM4P)**:
* Często skompresowany (LZFSE4, LZSS, …)
* Opcjonalnie szyfrowany
* **Manifest (IM4M)**:
* Zawiera podpis
* Dodatkowy słownik klucz/wartość
* **Restore Info (IM4R)**:
* Znany również jako APNonce
* Zapobiega powtarzaniu niektórych aktualizacji
* OPCJONALNE: Zwykle nie jest to znalezione

Dekompresuj Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Pobierz&#x20;

* [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

W [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) można znaleźć wszystkie zestawy debugowania jądra. Możesz je pobrać, zamontować, otworzyć za pomocą narzędzia [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), uzyskać dostęp do folderu **`.kext`** i **wyodrębnić go**.

Sprawdź go pod kątem symboli za pomocą:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
* [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Czasami Apple wydaje **kernelcache** z **symbolami**. Możesz pobrać niektóre firmware z symbolami, korzystając z linków na tych stronach. Firmware będzie zawierać **kernelcache** oraz inne pliki.

Aby **wyodrębnić** pliki, zacznij od zmiany rozszerzenia z `.ipsw` na `.zip` i **rozpakuj** je.

Po wyodrębnieniu firmware otrzymasz plik o nazwie: **`kernelcache.release.iphone14`**. Jest w formacie **IMG4**, możesz wyodrębnić interesujące informacje za pomocą:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspecting kernelcache

Sprawdź, czy kernelcache ma symbole z
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Z tym możemy teraz **wyodrębnić wszystkie rozszerzenia** lub **to, które Cię interesuje:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Referencje

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{% hint style="success" %}
Ucz się i ćwicz AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
