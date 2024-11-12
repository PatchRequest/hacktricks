# PsExec/Winexec/ScExec

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

## Jak to działa

Proces jest opisany w poniższych krokach, ilustrując, jak binaria usług są manipulowane w celu osiągnięcia zdalnego wykonania na docelowej maszynie za pośrednictwem SMB:

1. **Kopiowanie binariów usługi do udziału ADMIN$ przez SMB** jest wykonywane.
2. **Tworzenie usługi na zdalnej maszynie** odbywa się poprzez wskazanie na binarię.
3. Usługa jest **uruchamiana zdalnie**.
4. Po zakończeniu usługa jest **zatrzymywana, a binaria są usuwane**.

### **Proces ręcznego wykonywania PsExec**

Zakładając, że istnieje ładunek wykonywalny (stworzony za pomocą msfvenom i z obfuskowanym kodem przy użyciu Veil, aby uniknąć wykrycia przez programy antywirusowe), nazwany 'met8888.exe', reprezentujący ładunek meterpreter reverse_http, podejmowane są następujące kroki:

* **Kopiowanie binariów**: Wykonywalny plik jest kopiowany do udziału ADMIN$ z wiersza poleceń, chociaż może być umieszczony w dowolnym miejscu w systemie plików, aby pozostać ukrytym.
* **Tworzenie usługi**: Wykorzystując polecenie Windows `sc`, które pozwala na zapytania, tworzenie i usuwanie usług Windows zdalnie, tworzona jest usługa o nazwie "meterpreter", wskazująca na przesłaną binarię.
* **Uruchamianie usługi**: Ostatni krok polega na uruchomieniu usługi, co prawdopodobnie spowoduje błąd "time-out" z powodu tego, że binaria nie są prawdziwymi binariami usług i nie zwracają oczekiwanego kodu odpowiedzi. Ten błąd jest nieistotny, ponieważ głównym celem jest wykonanie binariów.

Obserwacja nasłuchiwacza Metasploit ujawni, że sesja została pomyślnie zainicjowana.

[Dowiedz się więcej o poleceniu `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Znajdź bardziej szczegółowe kroki w: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Możesz również użyć binariów Windows Sysinternals PsExec.exe:**

![](<../../.gitbook/assets/image (928).png>)

Możesz również użyć [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
