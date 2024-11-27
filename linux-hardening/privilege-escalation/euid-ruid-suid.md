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


### Variabili di Identificazione Utente

- **`ruid`**: Il **real user ID** indica l'utente che ha avviato il processo.
- **`euid`**: Conosciuto come **effective user ID**, rappresenta l'identità dell'utente utilizzata dal sistema per determinare i privilegi del processo. Generalmente, `euid` rispecchia `ruid`, tranne in casi come l'esecuzione di un binario SetUID, dove `euid` assume l'identità del proprietario del file, concedendo così specifici permessi operativi.
- **`suid`**: Questo **saved user ID** è fondamentale quando un processo ad alto privilegio (tipicamente in esecuzione come root) deve temporaneamente rinunciare ai propri privilegi per eseguire determinate operazioni, per poi riprendere successivamente il proprio stato elevato iniziale.

#### Nota Importante
Un processo che non opera sotto root può modificare il proprio `euid` solo per farlo corrispondere all'attuale `ruid`, `euid` o `suid`.

### Comprendere le Funzioni set*uid

- **`setuid`**: Contrariamente alle assunzioni iniziali, `setuid` modifica principalmente `euid` piuttosto che `ruid`. Specificamente, per i processi privilegiati, allinea `ruid`, `euid` e `suid` con l'utente specificato, spesso root, consolidando efficacemente questi ID a causa del `suid` sovrascritto. Informazioni dettagliate possono essere trovate nella [pagina man di setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** e **`setresuid`**: Queste funzioni consentono un aggiustamento sfumato di `ruid`, `euid` e `suid`. Tuttavia, le loro capacità dipendono dal livello di privilegio del processo. Per i processi non root, le modifiche sono limitate ai valori attuali di `ruid`, `euid` e `suid`. Al contrario, i processi root o quelli con la capacità `CAP_SETUID` possono assegnare valori arbitrari a questi ID. Maggiori informazioni possono essere ottenute dalla [pagina man di setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) e dalla [pagina man di setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Queste funzionalità non sono progettate come un meccanismo di sicurezza, ma per facilitare il flusso operativo previsto, come quando un programma adotta l'identità di un altro utente modificando il proprio effective user ID.

È importante notare che, sebbene `setuid` possa essere una scelta comune per l'elevazione dei privilegi a root (poiché allinea tutti gli ID a root), differenziare tra queste funzioni è cruciale per comprendere e manipolare i comportamenti degli ID utente in vari scenari.

### Meccanismi di Esecuzione dei Programmi in Linux

#### **Chiamata di Sistema `execve`**
- **Funzionalità**: `execve` avvia un programma, determinato dal primo argomento. Prende due argomenti array, `argv` per gli argomenti e `envp` per l'ambiente.
- **Comportamento**: Mantiene lo spazio di memoria del chiamante ma aggiorna lo stack, l'heap e i segmenti di dati. Il codice del programma viene sostituito dal nuovo programma.
- **Preservazione dell'ID Utente**:
- `ruid`, `euid` e gli ID di gruppo supplementari rimangono invariati.
- `euid` potrebbe subire cambiamenti sfumati se il nuovo programma ha impostato il bit SetUID.
- `suid` viene aggiornato da `euid` dopo l'esecuzione.
- **Documentazione**: Informazioni dettagliate possono essere trovate nella [pagina man di `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **Funzione `system`**
- **Funzionalità**: A differenza di `execve`, `system` crea un processo figlio utilizzando `fork` ed esegue un comando all'interno di quel processo figlio utilizzando `execl`.
- **Esecuzione del Comando**: Esegue il comando tramite `sh` con `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Comportamento**: Poiché `execl` è una forma di `execve`, opera in modo simile ma nel contesto di un nuovo processo figlio.
- **Documentazione**: Ulteriori informazioni possono essere ottenute dalla [pagina man di `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Comportamento di `bash` e `sh` con SUID**
- **`bash`**:
- Ha un'opzione `-p` che influisce su come vengono trattati `euid` e `ruid`.
- Senza `-p`, `bash` imposta `euid` su `ruid` se inizialmente differiscono.
- Con `-p`, l'iniziale `euid` viene preservato.
- Maggiori dettagli possono essere trovati nella [pagina man di `bash`](https://linux.die.net/man/1/bash).
- **`sh`**:
- Non possiede un meccanismo simile a `-p` in `bash`.
- Il comportamento riguardante gli ID utente non è esplicitamente menzionato, tranne che sotto l'opzione `-i`, enfatizzando la preservazione dell'uguaglianza tra `euid` e `ruid`.
- Ulteriori informazioni sono disponibili sulla [pagina man di `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Questi meccanismi, distinti nel loro funzionamento, offrono una gamma versatile di opzioni per eseguire e passare tra programmi, con specifiche sfumature su come gli ID utente vengono gestiti e preservati.

### Testare i Comportamenti degli ID Utente nelle Esecuzioni

Esempi tratti da https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, controlla per ulteriori informazioni

#### Caso 1: Utilizzare `setuid` con `system`

**Obiettivo**: Comprendere l'effetto di `setuid` in combinazione con `system` e `bash` come `sh`.

**Codice C**:
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
**Compilazione e Permessi:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

* `ruid` ed `euid` iniziano come 99 (nobody) e 1000 (frank) rispettivamente.
* `setuid` allinea entrambi a 1000.
* `system` esegue `/bin/bash -c id` a causa del symlink da sh a bash.
* `bash`, senza `-p`, regola `euid` per corrispondere a `ruid`, risultando in entrambi a 99 (nobody).

#### Caso 2: Utilizzando setreuid con system

**Codice C**:
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
**Compilazione e Permessi:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Esecuzione e Risultato:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

* `setreuid` imposta sia ruid che euid a 1000.
* `system` invoca bash, che mantiene gli ID utente a causa della loro uguaglianza, operando effettivamente come frank.

#### Caso 3: Utilizzo di setuid con execve
Obiettivo: Esplorare l'interazione tra setuid ed execve.
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
**Esecuzione e Risultato:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

* `ruid` rimane 99, ma euid è impostato su 1000, in linea con l'effetto di setuid.

**Esempio di codice C 2 (Chiamando Bash):**
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
**Esecuzione e Risultato:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

* Anche se `euid` è impostato a 1000 da `setuid`, `bash` ripristina euid a `ruid` (99) a causa dell'assenza di `-p`.

**Esempio di codice C 3 (Utilizzando bash -p):**
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
**Esecuzione e Risultato:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Riferimenti
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Approfondisci la tua esperienza in **Mobile Security** con 8kSec Academy. Padroneggia la sicurezza di iOS e Android attraverso i nostri corsi autogestiti e ottieni una certificazione:

{% embed url="https://academy.8ksec.io/" %}


{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
