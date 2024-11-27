# euid, ruid, suid

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Panua ujuzi wako katika **Usalama wa Simu** na 8kSec Academy. Master usalama wa iOS na Android kupitia kozi zetu za kujifunza kwa kasi yako na upate cheti:

{% embed url="https://academy.8ksec.io/" %}


### Mabadiliko ya Utambulisho wa Mtumiaji

- **`ruid`**: **kitambulisho halisi cha mtumiaji** kinamaanisha mtumiaji aliyeanzisha mchakato.
- **`euid`**: Inajulikana kama **kitambulisho cha mtumiaji kinachofanya kazi**, inawakilisha utambulisho wa mtumiaji unaotumiwa na mfumo kubaini ruhusa za mchakato. Kwa ujumla, `euid` inafanana na `ruid`, isipokuwa katika matukio kama utekelezaji wa binary ya SetUID, ambapo `euid` inachukua utambulisho wa mmiliki wa faili, hivyo kutoa ruhusa maalum za uendeshaji.
- **`suid`**: Huu **ni kitambulisho kilichohifadhiwa cha mtumiaji** ambacho ni muhimu wakati mchakato wa juu wa ruhusa (kawaida ukifanya kazi kama root) unahitaji kuachilia kwa muda ruhusa zake ili kutekeleza kazi fulani, kisha baadaye kurejesha hadhi yake ya juu ya awali.

#### Kumbuka Muhimu
Mchakato usiokuwa chini ya root unaweza kubadilisha `euid` yake ili ifanane na `ruid`, `euid`, au `suid` ya sasa.

### Kuelewa set*uid Functions

- **`setuid`**: Kinyume na dhana za awali, `setuid` inabadilisha hasa `euid` badala ya `ruid`. Kwa mchakato wenye ruhusa, inalinganisha `ruid`, `euid`, na `suid` na mtumiaji aliyeainishwa, mara nyingi root, kwa ufanisi inaimarisha vitambulisho hivi kutokana na `suid` inayoshinda. Maelezo ya kina yanaweza kupatikana kwenye [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** na **`setresuid`**: Hizi kazi zinaruhusu marekebisho ya kina ya `ruid`, `euid`, na `suid`. Hata hivyo, uwezo wao unategemea kiwango cha ruhusa za mchakato. Kwa michakato isiyo ya root, marekebisho yanakabiliwa na thamani za sasa za `ruid`, `euid`, na `suid`. Kwa upande mwingine, michakato ya root au ile yenye uwezo wa `CAP_SETUID` inaweza kupewa thamani zisizo za kawaida kwa vitambulisho hivi. Maelezo zaidi yanaweza kupatikana kwenye [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) na [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Hizi kazi zimeundwa si kama mekanismu ya usalama bali kusaidia mtiririko wa uendeshaji unaokusudiwa, kama vile wakati programu inachukua utambulisho wa mtumiaji mwingine kwa kubadilisha kitambulisho chake cha mtumiaji kinachofanya kazi.

Kwa kuzingatia, ingawa `setuid` inaweza kuwa chaguo la kawaida kwa ajili ya kupandisha ruhusa hadi root (kwa kuwa inalinganisha vitambulisho vyote na root), kutofautisha kati ya hizi kazi ni muhimu kwa kuelewa na kudhibiti tabia za kitambulisho cha mtumiaji katika hali tofauti.

### Mifumo ya Utekelezaji wa Programu katika Linux

#### **`execve` System Call**
- **Kazi**: `execve` inaanzisha programu, inayoamuliwa na hoja ya kwanza. Inachukua hoja mbili za array, `argv` kwa ajili ya hoja na `envp` kwa ajili ya mazingira.
- **Tabia**: Inahifadhi nafasi ya kumbukumbu ya mwituni lakini inasasisha stack, heap, na sehemu za data. Kanuni ya programu inabadilishwa na programu mpya.
- **Uhifadhi wa Kitambulisho cha Mtumiaji**:
- `ruid`, `euid`, na vitambulisho vya kikundi vya ziada vinabaki bila kubadilika.
- `euid` inaweza kuwa na mabadiliko madogo ikiwa programu mpya ina SetUID bit iliyoanzishwa.
- `suid` inasasishwa kutoka `euid` baada ya utekelezaji.
- **Nyaraka**: Maelezo ya kina yanaweza kupatikana kwenye [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **`system` Function**
- **Kazi**: Kinyume na `execve`, `system` inaunda mchakato wa mtoto kwa kutumia `fork` na inatekeleza amri ndani ya mchakato huo wa mtoto kwa kutumia `execl`.
- **Utekelezaji wa Amri**: Inatekeleza amri kupitia `sh` kwa kutumia `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Tabia**: Kwa kuwa `execl` ni aina ya `execve`, inafanya kazi kwa njia sawa lakini katika muktadha wa mchakato mpya wa mtoto.
- **Nyaraka**: Maelezo zaidi yanaweza kupatikana kwenye [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Tabia ya `bash` na `sh` na SUID**
- **`bash`**:
- Ina chaguo la `-p` linaloathiri jinsi `euid` na `ruid` zinavyoshughulikiwa.
- Bila `-p`, `bash` inabadilisha `euid` kuwa `ruid` ikiwa awali zinatofautiana.
- Kwa `-p`, `euid` ya awali inahifadhiwa.
- Maelezo zaidi yanaweza kupatikana kwenye [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Haina mekanismu kama `-p` katika `bash`.
- Tabia inayohusiana na vitambulisho vya mtumiaji haijatajwa wazi, isipokuwa chini ya chaguo la `-i`, ikisisitiza uhifadhi wa usawa wa `euid` na `ruid`.
- Maelezo zaidi yanaweza kupatikana kwenye [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Mifumo hii, tofauti katika uendeshaji wao, inatoa anuwai ya chaguzi za kutekeleza na kubadilisha kati ya programu, ikiwa na nuances maalum katika jinsi vitambulisho vya mtumiaji vinavyoshughulikiwa na kuhifadhiwa.

### Kuangalia Tabia za Kitambulisho cha Mtumiaji katika Utekelezaji

Mifano imechukuliwa kutoka https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, angalia kwa maelezo zaidi

#### Kesi ya 1: Kutumia `setuid` na `system`

**Lengo**: Kuelewa athari ya `setuid` kwa pamoja na `system` na `bash` kama `sh`.

**C Code**:
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
**Uundaji na Ruhusa:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analysis:**

* `ruid` na `euid` huanza kama 99 (nobody) na 1000 (frank) mtawalia.
* `setuid` inawalinganisha wote kuwa 1000.
* `system` inatekeleza `/bin/bash -c id` kutokana na symlink kutoka sh hadi bash.
* `bash`, bila `-p`, inarekebisha `euid` ili ifanane na `ruid`, na kusababisha wote kuwa 99 (nobody).

#### Case 2: Using setreuid with system

**C Code**:
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
**Uundaji na Ruhusa:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analysis:**

* `setreuid` inafanya ruid na euid kuwa 1000.
* `system` inaita bash, ambayo inashikilia vitambulisho vya mtumiaji kutokana na usawa wao, ikifanya kazi kama frank.

#### Case 3: Using setuid with execve
Objective: Kuchunguza mwingiliano kati ya setuid na execve.
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
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analysis:**

* `ruid` inabaki 99, lakini euid imewekwa kwa 1000, kulingana na athari ya setuid.

**C Code Example 2 (Calling Bash):**
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
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analysis:**

* Ingawa `euid` imewekwa kuwa 1000 na `setuid`, `bash` inarejesha euid kuwa `ruid` (99) kutokana na ukosefu wa `-p`.

**C Code Example 3 (Using bash -p):**
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
**Utekelezaji na Matokeo:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## References
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}


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
