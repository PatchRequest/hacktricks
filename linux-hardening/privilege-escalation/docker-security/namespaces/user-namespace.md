# User Namespace

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Basic Information

Przestrzeń nazw użytkowników to funkcja jądra Linux, która **zapewnia izolację mapowań identyfikatorów użytkowników i grup**, pozwalając każdej przestrzeni nazw użytkowników na posiadanie **własnego zestawu identyfikatorów użytkowników i grup**. Ta izolacja umożliwia procesom działającym w różnych przestrzeniach nazw użytkowników **posiadanie różnych uprawnień i własności**, nawet jeśli dzielą te same identyfikatory użytkowników i grup numerycznie.

Przestrzenie nazw użytkowników są szczególnie przydatne w konteneryzacji, gdzie każdy kontener powinien mieć swój niezależny zestaw identyfikatorów użytkowników i grup, co pozwala na lepsze bezpieczeństwo i izolację między kontenerami a systemem gospodarza.

### How it works:

1. Gdy tworzona jest nowa przestrzeń nazw użytkowników, **zaczyna się od pustego zestawu mapowań identyfikatorów użytkowników i grup**. Oznacza to, że każdy proces działający w nowej przestrzeni nazw użytkowników **początkowo nie będzie miał uprawnień poza tą przestrzenią**.
2. Mapowania identyfikatorów mogą być ustalane między identyfikatorami użytkowników i grup w nowej przestrzeni a tymi w przestrzeni nadrzędnej (lub gospodarza). To **pozwala procesom w nowej przestrzeni na posiadanie uprawnień i własności odpowiadających identyfikatorom użytkowników i grup w przestrzeni nadrzędnej**. Jednak mapowania identyfikatorów mogą być ograniczone do określonych zakresów i podzbiorów identyfikatorów, co pozwala na precyzyjną kontrolę nad uprawnieniami przyznawanymi procesom w nowej przestrzeni.
3. W obrębie przestrzeni nazw użytkowników **procesy mogą mieć pełne uprawnienia roota (UID 0) do operacji wewnątrz przestrzeni**, jednocześnie mając ograniczone uprawnienia poza tą przestrzenią. To pozwala **kontenerom działać z możliwościami podobnymi do roota w ich własnej przestrzeni, nie mając pełnych uprawnień roota w systemie gospodarza**.
4. Procesy mogą przemieszczać się między przestrzeniami nazw, używając wywołania systemowego `setns()` lub tworzyć nowe przestrzenie nazw, używając wywołań systemowych `unshare()` lub `clone()` z flagą `CLONE_NEWUSER`. Gdy proces przemieszcza się do nowej przestrzeni lub ją tworzy, zacznie używać mapowań identyfikatorów użytkowników i grup związanych z tą przestrzenią.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Mountując nową instancję systemu plików `/proc`, używając parametru `--mount-proc`, zapewniasz, że nowa przestrzeń montowania ma **dokładny i izolowany widok informacji o procesach specyficznych dla tej przestrzeni**.

<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy `unshare` jest wykonywane bez opcji `-f`, napotykany jest błąd z powodu sposobu, w jaki Linux obsługuje nowe przestrzenie nazw PID (identyfikator procesu). Kluczowe szczegóły i rozwiązanie są opisane poniżej:

1. **Wyjaśnienie problemu**:
- Jądro Linuxa pozwala procesowi na tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany "procesem unshare"), nie wchodzi do nowej przestrzeni; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` uruchamia `/bin/bash` w tym samym procesie co `unshare`. W konsekwencji, `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni staje się PID 1. Gdy ten proces kończy działanie, uruchamia czyszczenie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania osieroconych procesów. Jądro Linuxa wyłączy wtedy przydzielanie PID w tej przestrzeni.

2. **Konsekwencja**:
- Zakończenie PID 1 w nowej przestrzeni prowadzi do wyczyszczenia flagi `PIDNS_HASH_ADDING`. Skutkuje to niepowodzeniem funkcji `alloc_pid` w przydzieleniu nowego PID podczas tworzenia nowego procesu, co skutkuje błędem "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` z `unshare`. Ta opcja sprawia, że `unshare` fork'uje nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że polecenie `unshare` samo staje się PID 1 w nowej przestrzeni. `/bin/bash` i jego procesy potomne są wtedy bezpiecznie zawarte w tej nowej przestrzeni, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Zapewniając, że `unshare` działa z flagą `-f`, nowa przestrzeń nazw PID jest prawidłowo utrzymywana, co pozwala `/bin/bash` i jego podprocesom działać bez napotkania błędu przydzielania pamięci.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Aby użyć przestrzeni nazw użytkownika, demon Dockera musi być uruchomiony z **`--userns-remap=default`** (W ubuntu 14.04 można to zrobić, modyfikując `/etc/default/docker`, a następnie wykonując `sudo service docker restart`)

### &#x20;Sprawdź, w której przestrzeni nazw znajduje się twój proces
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Można sprawdzić mapę użytkowników z kontenera docker za pomocą:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Lub z hosta za pomocą:
```bash
cat /proc/<pid>/uid_map
```
### Znajdź wszystkie przestrzenie nazw użytkowników

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Wejście do przestrzeni nazw użytkownika
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Również, możesz **wejść do innej przestrzeni nazw procesu tylko jeśli jesteś root**. I **nie możesz** **wejść** do innej przestrzeni nazw **bez deskryptora** wskazującego na nią (jak `/proc/self/ns/user`).

### Utwórz nową przestrzeń nazw użytkownika (z mapowaniami)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Odzyskiwanie uprawnień

W przypadku przestrzeni nazw użytkowników, **gdy tworzona jest nowa przestrzeń nazw użytkowników, proces, który wchodzi do tej przestrzeni, otrzymuje pełny zestaw uprawnień w tej przestrzeni**. Te uprawnienia pozwalają procesowi na wykonywanie operacji uprzywilejowanych, takich jak **montowanie** **systemów plików**, tworzenie urządzeń czy zmiana właściciela plików, ale **tylko w kontekście jego przestrzeni nazw użytkowników**.

Na przykład, gdy masz uprawnienie `CAP_SYS_ADMIN` w przestrzeni nazw użytkowników, możesz wykonywać operacje, które zazwyczaj wymagają tego uprawnienia, takie jak montowanie systemów plików, ale tylko w kontekście swojej przestrzeni nazw użytkowników. Jakiekolwiek operacje, które wykonasz z tym uprawnieniem, nie wpłyną na system gospodarza ani inne przestrzenie nazw.

{% hint style="warning" %}
Dlatego, nawet jeśli uzyskanie nowego procesu w nowej przestrzeni nazw użytkowników **przywróci ci wszystkie uprawnienia** (CapEff: 000001ffffffffff), w rzeczywistości możesz **używać tylko tych związanych z przestrzenią nazw** (na przykład montowanie), a nie wszystkich. Tak więc, samo to nie wystarczy, aby uciec z kontenera Docker.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
