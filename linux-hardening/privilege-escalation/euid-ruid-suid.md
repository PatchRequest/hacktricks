# euid, ruid, suid

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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}


### Zmienne identyfikacji użytkownika

- **`ruid`**: **rzeczywisty identyfikator użytkownika** oznacza użytkownika, który zainicjował proces.
- **`euid`**: Znany jako **efektywny identyfikator użytkownika**, reprezentuje tożsamość użytkownika wykorzystywaną przez system do ustalenia uprawnień procesu. Zazwyczaj `euid` odzwierciedla `ruid`, z wyjątkiem przypadków takich jak wykonanie binarnego pliku SetUID, gdzie `euid` przyjmuje tożsamość właściciela pliku, co przyznaje określone uprawnienia operacyjne.
- **`suid`**: Ten **zapisany identyfikator użytkownika** jest kluczowy, gdy proces o wysokich uprawnieniach (zwykle działający jako root) musi tymczasowo zrezygnować ze swoich uprawnień, aby wykonać określone zadania, a następnie odzyskać swój początkowy podwyższony status.

#### Ważna uwaga
Proces, który nie działa jako root, może zmienić swój `euid` tylko na wartość odpowiadającą bieżącemu `ruid`, `euid` lub `suid`.

### Zrozumienie funkcji set*uid

- **`setuid`**: W przeciwieństwie do początkowych założeń, `setuid` głównie modyfikuje `euid`, a nie `ruid`. W szczególności dla procesów z uprawnieniami, synchronizuje `ruid`, `euid` i `suid` z określonym użytkownikiem, często root, skutecznie utrwalając te identyfikatory z powodu dominującego `suid`. Szczegółowe informacje można znaleźć na [stronie podręcznika setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** i **`setresuid`**: Te funkcje pozwalają na subtelną regulację `ruid`, `euid` i `suid`. Jednak ich możliwości są uzależnione od poziomu uprawnień procesu. Dla procesów niebędących root, modyfikacje są ograniczone do bieżących wartości `ruid`, `euid` i `suid`. W przeciwieństwie do tego, procesy root lub te z uprawnieniem `CAP_SETUID` mogą przypisywać dowolne wartości tym identyfikatorom. Więcej informacji można znaleźć na [stronie podręcznika setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) i [stronie podręcznika setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Te funkcjonalności nie są zaprojektowane jako mechanizm zabezpieczający, ale mają na celu ułatwienie zamierzonego przepływu operacyjnego, na przykład, gdy program przyjmuje tożsamość innego użytkownika, zmieniając swój efektywny identyfikator użytkownika.

Warto zauważyć, że podczas gdy `setuid` może być powszechnie stosowane do podnoszenia uprawnień do roota (ponieważ synchronizuje wszystkie identyfikatory z root), rozróżnienie między tymi funkcjami jest kluczowe dla zrozumienia i manipulowania zachowaniami identyfikatorów użytkowników w różnych scenariuszach.

### Mechanizmy wykonywania programów w Linuxie

#### **Wywołanie systemowe `execve`**
- **Funkcjonalność**: `execve` inicjuje program, określony przez pierwszy argument. Przyjmuje dwa argumenty tablicowe, `argv` dla argumentów i `envp` dla środowiska.
- **Zachowanie**: Zachowuje przestrzeń pamięci wywołującego, ale odświeża stos, stertę i segmenty danych. Kod programu jest zastępowany przez nowy program.
- **Zachowanie identyfikatora użytkownika**:
- `ruid`, `euid` i dodatkowe identyfikatory grupowe pozostają niezmienione.
- `euid` może mieć subtelne zmiany, jeśli nowy program ma ustawiony bit SetUID.
- `suid` jest aktualizowany z `euid` po wykonaniu.
- **Dokumentacja**: Szczegółowe informacje można znaleźć na [stronie podręcznika `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **Funkcja `system`**
- **Funkcjonalność**: W przeciwieństwie do `execve`, `system` tworzy proces potomny za pomocą `fork` i wykonuje polecenie w tym procesie potomnym za pomocą `execl`.
- **Wykonanie polecenia**: Wykonuje polecenie za pośrednictwem `sh` z `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Zachowanie**: Ponieważ `execl` jest formą `execve`, działa podobnie, ale w kontekście nowego procesu potomnego.
- **Dokumentacja**: Dalsze informacje można uzyskać z [strony podręcznika `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Zachowanie `bash` i `sh` z SUID**
- **`bash`**:
- Ma opcję `-p`, która wpływa na to, jak traktowane są `euid` i `ruid`.
- Bez `-p`, `bash` ustawia `euid` na `ruid`, jeśli początkowo się różnią.
- Z `-p`, początkowe `euid` jest zachowywane.
- Więcej szczegółów można znaleźć na [stronie podręcznika `bash`](https://linux.die.net/man/1/bash).
- **`sh`**:
- Nie ma mechanizmu podobnego do `-p` w `bash`.
- Zachowanie dotyczące identyfikatorów użytkowników nie jest wyraźnie wspomniane, z wyjątkiem opcji `-i`, podkreślającej zachowanie równości `euid` i `ruid`.
- Dodatkowe informacje są dostępne na [stronie podręcznika `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Te mechanizmy, różniące się w swoim działaniu, oferują wszechstronny zakres opcji do wykonywania i przechodzenia między programami, z określonymi niuansami w zarządzaniu i zachowywaniu identyfikatorów użytkowników.

### Testowanie zachowań identyfikatorów użytkowników w wykonaniach

Przykłady zaczerpnięte z https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, sprawdź to dla dalszych informacji

#### Przypadek 1: Użycie `setuid` z `system`

**Cel**: Zrozumienie wpływu `setuid` w połączeniu z `system` i `bash` jako `sh`.

**Kod C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Kompilacja i uprawnienia:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

* `ruid` i `euid` zaczynają jako 99 (nikt) i 1000 (frank) odpowiednio.
* `setuid` ustawia oba na 1000.
* `system` wykonuje `/bin/bash -c id` z powodu symlink z sh do bash.
* `bash`, bez `-p`, dostosowuje `euid` do `ruid`, co skutkuje tym, że oba są 99 (nikt).

#### Przypadek 2: Użycie setreuid z system

**Kod C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Kompilacja i uprawnienia:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Wykonanie i wynik:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

* `setreuid` ustawia zarówno ruid, jak i euid na 1000.
* `system` wywołuje bash, który utrzymuje identyfikatory użytkowników z powodu ich równości, skutecznie działając jako frank.

#### Przypadek 3: Użycie setuid z execve
Cel: Badanie interakcji między setuid a execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Wykonanie i wynik:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

* `ruid` pozostaje 99, ale euid jest ustawiony na 1000, zgodnie z efektem setuid.

**Przykład kodu C 2 (Wywołanie Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Wykonanie i wynik:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

* Chociaż `euid` jest ustawione na 1000 przez `setuid`, `bash` resetuje euid do `ruid` (99) z powodu braku `-p`.

**Przykład kodu C 3 (Używając bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Wykonanie i wynik:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## References
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Zgłębiaj swoją wiedzę w zakresie **Mobile Security** z 8kSec Academy. Opanuj bezpieczeństwo iOS i Androida dzięki naszym kursom w trybie samodzielnym i zdobądź certyfikat:

{% embed url="https://academy.8ksec.io/" %}


{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
