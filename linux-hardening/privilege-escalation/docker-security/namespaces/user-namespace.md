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

Un namespace utente è una funzionalità del kernel Linux che **fornisce isolamento delle mappature degli ID utente e gruppo**, consentendo a ciascun namespace utente di avere il **proprio insieme di ID utente e gruppo**. Questo isolamento consente ai processi in esecuzione in diversi namespace utente di **avere privilegi e proprietà diversi**, anche se condividono gli stessi ID utente e gruppo numericamente.

I namespace utente sono particolarmente utili nella containerizzazione, dove ogni container dovrebbe avere il proprio insieme indipendente di ID utente e gruppo, consentendo una migliore sicurezza e isolamento tra i container e il sistema host.

### How it works:

1. Quando viene creato un nuovo namespace utente, **inizia con un insieme vuoto di mappature degli ID utente e gruppo**. Ciò significa che qualsiasi processo in esecuzione nel nuovo namespace utente avrà **inizialmente nessun privilegio al di fuori del namespace**.
2. Le mappature degli ID possono essere stabilite tra gli ID utente e gruppo nel nuovo namespace e quelli nel namespace genitore (o host). Questo **consente ai processi nel nuovo namespace di avere privilegi e proprietà corrispondenti agli ID utente e gruppo nel namespace genitore**. Tuttavia, le mappature degli ID possono essere limitate a intervalli e sottoinsiemi specifici di ID, consentendo un controllo dettagliato sui privilegi concessi ai processi nel nuovo namespace.
3. All'interno di un namespace utente, **i processi possono avere pieni privilegi di root (UID 0) per le operazioni all'interno del namespace**, pur avendo privilegi limitati al di fuori del namespace. Questo consente **ai container di funzionare con capacità simili a root all'interno del proprio namespace senza avere pieni privilegi di root sul sistema host**.
4. I processi possono spostarsi tra i namespace utilizzando la chiamata di sistema `setns()` o creare nuovi namespace utilizzando le chiamate di sistema `unshare()` o `clone()` con il flag `CLONE_NEWUSER`. Quando un processo si sposta in un nuovo namespace o ne crea uno, inizierà a utilizzare le mappature degli ID utente e gruppo associate a quel namespace.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Montando una nuova istanza del filesystem `/proc` se utilizzi il parametro `--mount-proc`, garantisci che il nuovo namespace di mount abbia una **visione accurata e isolata delle informazioni sui processi specifiche per quel namespace**.

<details>

<summary>Errore: bash: fork: Impossibile allocare memoria</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si verifica un errore a causa del modo in cui Linux gestisce i nuovi namespace PID (Process ID). I dettagli chiave e la soluzione sono delineati di seguito:

1. **Spiegazione del problema**:
- Il kernel Linux consente a un processo di creare nuovi namespace utilizzando la chiamata di sistema `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo namespace PID (denominato processo "unshare") non entra nel nuovo namespace; solo i suoi processi figli lo fanno.
- Eseguire `%unshare -p /bin/bash%` avvia `/bin/bash` nello stesso processo di `unshare`. Di conseguenza, `/bin/bash` e i suoi processi figli si trovano nel namespace PID originale.
- Il primo processo figlio di `/bin/bash` nel nuovo namespace diventa PID 1. Quando questo processo termina, attiva la pulizia del namespace se non ci sono altri processi, poiché PID 1 ha il ruolo speciale di adottare processi orfani. Il kernel Linux disabiliterà quindi l'allocazione PID in quel namespace.

2. **Conseguenza**:
- L'uscita di PID 1 in un nuovo namespace porta alla pulizia del flag `PIDNS_HASH_ADDING`. Questo porta al fallimento della funzione `alloc_pid` nell'allocare un nuovo PID durante la creazione di un nuovo processo, producendo l'errore "Impossibile allocare memoria".

3. **Soluzione**:
- Il problema può essere risolto utilizzando l'opzione `-f` con `unshare`. Questa opzione fa sì che `unshare` fork un nuovo processo dopo aver creato il nuovo namespace PID.
- Eseguire `%unshare -fp /bin/bash%` garantisce che il comando `unshare` stesso diventi PID 1 nel nuovo namespace. `/bin/bash` e i suoi processi figli sono quindi contenuti in modo sicuro all'interno di questo nuovo namespace, prevenendo l'uscita prematura di PID 1 e consentendo l'allocazione normale dei PID.

Assicurandoti che `unshare` venga eseguito con il flag `-f`, il nuovo namespace PID viene mantenuto correttamente, consentendo a `/bin/bash` e ai suoi subprocessi di operare senza incontrare l'errore di allocazione della memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Per utilizzare il namespace utente, il demone Docker deve essere avviato con **`--userns-remap=default`** (In ubuntu 14.04, questo può essere fatto modificando `/etc/default/docker` e poi eseguendo `sudo service docker restart`)

### &#x20;Controlla in quale namespace si trova il tuo processo
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
È possibile controllare la mappa degli utenti dal container docker con:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
O dal host con:
```bash
cat /proc/<pid>/uid_map
```
### Trova tutti i namespace utente

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entra all'interno di un User namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Inoltre, puoi **entrare in un altro namespace di processo solo se sei root**. E **non puoi** **entrare** in un altro namespace **senza un descrittore** che punti ad esso (come `/proc/self/ns/user`).

### Crea un nuovo namespace utente (con mappature)

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
### Recupero delle Capacità

Nel caso degli user namespaces, **quando viene creato un nuovo user namespace, il processo che entra nello namespace riceve un insieme completo di capacità all'interno di quello namespace**. Queste capacità consentono al processo di eseguire operazioni privilegiate come **montare** **filesystem**, creare dispositivi o cambiare la proprietà dei file, ma **solo nel contesto del proprio user namespace**.

Ad esempio, quando hai la capacità `CAP_SYS_ADMIN` all'interno di un user namespace, puoi eseguire operazioni che normalmente richiedono questa capacità, come montare filesystem, ma solo nel contesto del tuo user namespace. Qualsiasi operazione che esegui con questa capacità non influenzerà il sistema host o altri namespace.

{% hint style="warning" %}
Pertanto, anche se ottenere un nuovo processo all'interno di un nuovo User namespace **ti restituirà tutte le capacità** (CapEff: 000001ffffffffff), in realtà puoi **utilizzare solo quelle relative allo namespace** (montaggio ad esempio) ma non tutte. Quindi, questo da solo non è sufficiente per sfuggire a un container Docker.
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
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

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
