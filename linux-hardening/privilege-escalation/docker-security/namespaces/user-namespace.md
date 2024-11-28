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

User namespace je funkcija Linux kernela koja **omogućava izolaciju mapiranja korisničkih i grupnih ID-ova**, omogućavajući svakom korisničkom prostoru da ima **svoj set korisničkih i grupnih ID-ova**. Ova izolacija omogućava procesima koji se izvršavaju u različitim korisničkim prostorima da **imaju različite privilegije i vlasništvo**, čak i ako dele iste korisničke i grupne ID-ove numerički.

Korisnički prostori su posebno korisni u kontejnerizaciji, gde svaki kontejner treba da ima svoj nezavistan set korisničkih i grupnih ID-ova, omogućavajući bolju sigurnost i izolaciju između kontejnera i host sistema.

### How it works:

1. Kada se kreira novi korisnički prostor, on **počinje sa praznim setom mapiranja korisničkih i grupnih ID-ova**. To znači da bilo koji proces koji se izvršava u novom korisničkom prostoru **prvobitno neće imati privilegije van prostora**.
2. Mapiranja ID-ova mogu se uspostaviti između korisničkih i grupnih ID-ova u novom prostoru i onih u roditeljskom (ili host) prostoru. Ovo **omogućava procesima u novom prostoru da imaju privilegije i vlasništvo koja odgovaraju korisničkim i grupnim ID-ovima u roditeljskom prostoru**. Međutim, mapiranja ID-ova mogu biti ograničena na specifične opsege i podskupove ID-ova, omogućavajući preciznu kontrolu nad privilegijama dodeljenim procesima u novom prostoru.
3. Unutar korisničkog prostora, **procesi mogu imati pune root privilegije (UID 0) za operacije unutar prostora**, dok i dalje imaju ograničene privilegije van prostora. Ovo omogućava **kontejnerima da rade sa root-sličnim sposobnostima unutar svog prostora bez punih root privilegija na host sistemu**.
4. Procesi mogu prelaziti između prostora koristeći `setns()` sistemski poziv ili kreirati nove prostore koristeći `unshare()` ili `clone()` sistemske pozive sa `CLONE_NEWUSER` zastavicom. Kada proces pređe u novi prostor ili ga kreira, počeće da koristi mapiranja korisničkih i grupnih ID-ova povezanih sa tim prostorom.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Montiranjem nove instance `/proc` datotečnog sistema ako koristite parametar `--mount-proc`, osiguravate da nova mount namespace ima **tačan i izolovan prikaz informacija o procesima specifičnim za tu namespace**.

<details>

<summary>Greška: bash: fork: Ne može da alocira memoriju</summary>

Kada se `unshare` izvrši bez `-f` opcije, dolazi do greške zbog načina na koji Linux upravlja novim PID (ID procesa) namespace-ima. Ključni detalji i rešenje su navedeni u nastavku:

1. **Objašnjenje problema**:
- Linux kernel omogućava procesu da kreira nove namespace-e koristeći `unshare` sistemski poziv. Međutim, proces koji inicira kreiranje novog PID namespace-a (poznat kao "unshare" proces) ne ulazi u novi namespace; samo njegovi podprocesi to čine.
- Pokretanjem `%unshare -p /bin/bash%` pokreće se `/bin/bash` u istom procesu kao `unshare`. Kao rezultat, `/bin/bash` i njegovi podprocesi su u originalnom PID namespace-u.
- Prvi podproces `/bin/bash` u novom namespace-u postaje PID 1. Kada ovaj proces izađe, pokreće čišćenje namespace-a ako nema drugih procesa, jer PID 1 ima posebnu ulogu usvajanja orfanskih procesa. Linux kernel će tada onemogućiti alokaciju PID-a u tom namespace-u.

2. **Posledica**:
- Izlazak PID 1 u novom namespace-u dovodi do čišćenja `PIDNS_HASH_ADDING` oznake. To rezultira neuspehom funkcije `alloc_pid` da alocira novi PID prilikom kreiranja novog procesa, što proizvodi grešku "Ne može da alocira memoriju".

3. **Rešenje**:
- Problem se može rešiti korišćenjem `-f` opcije sa `unshare`. Ova opcija čini da `unshare` fork-uje novi proces nakon kreiranja novog PID namespace-a.
- Izvršavanje `%unshare -fp /bin/bash%` osigurava da `unshare` komanda sama postane PID 1 u novom namespace-u. `/bin/bash` i njegovi podprocesi su tada sigurno sadržani unutar ovog novog namespace-a, sprečavajući prevremeni izlazak PID 1 i omogućavajući normalnu alokaciju PID-a.

Osiguravanjem da `unshare` radi sa `-f` oznakom, novi PID namespace se ispravno održava, omogućavajući `/bin/bash` i njegove podprocese da funkcionišu bez susretanja greške u alokaciji memorije.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Da biste koristili korisnički prostor, Docker demon treba da se pokrene sa **`--userns-remap=default`** (U ubuntu 14.04, to se može uraditi modifikovanjem `/etc/default/docker` i zatim izvršavanjem `sudo service docker restart`)

### &#x20;Proverite u kojem je prostoru vaš proces
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Moguće je proveriti mapu korisnika iz docker kontejnera sa:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Ili sa hosta sa:
```bash
cat /proc/<pid>/uid_map
```
### Pronađite sve korisničke imenske prostore

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Uđite unutar User namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Takođe, možete **ući u drugi procesni prostor imena samo ako ste root**. I **ne možete** **ući** u drugi prostor imena **bez deskriptora** koji na njega ukazuje (kao što je `/proc/self/ns/user`).

### Kreirajte novi prostor imena korisnika (sa mapiranjima)

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
### Oporavak sposobnosti

U slučaju korisničkih prostora, **kada se kreira novi korisnički prostor, procesu koji ulazi u prostor dodeljuje se potpuni skup sposobnosti unutar tog prostora**. Ove sposobnosti omogućavaju procesu da izvršava privilegovane operacije kao što su **montiranje** **fajl sistema**, kreiranje uređaja ili promena vlasništva nad fajlovima, ali **samo unutar konteksta svog korisničkog prostora**.

Na primer, kada imate sposobnost `CAP_SYS_ADMIN` unutar korisničkog prostora, možete izvršavati operacije koje obično zahtevaju ovu sposobnost, poput montiranja fajl sistema, ali samo unutar konteksta vašeg korisničkog prostora. Sve operacije koje izvršavate sa ovom sposobnošću neće uticati na host sistem ili druge prostore.

{% hint style="warning" %}
Stoga, čak i ako dobijanje novog procesa unutar novog korisničkog prostora **će vam vratiti sve sposobnosti** (CapEff: 000001ffffffffff), zapravo možete **koristiti samo one koje se odnose na prostor** (montiranje na primer) ali ne svaku. Dakle, ovo samo po sebi nije dovoljno da pobegnete iz Docker kontejnera.
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
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hacking trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}hacking trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

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
