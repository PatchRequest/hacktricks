# Εξ expose τοπικό στο διαδίκτυο

{% hint style="success" %}
Μάθε & εξάσκησε το AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε το GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Έλεγξε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετοχή στο** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) ή στο [**telegram group**](https://t.me/peass) ή **ακολούθησέ** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιράσου κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**Ο στόχος αυτής της σελίδας είναι να προτείνει εναλλακτικές που επιτρέπουν τουλάχιστον την έκθεση τοπικών raw TCP θυρών και τοπικών ιστότοπων (HTTP) στο διαδίκτυο χωρίς να χρειάζεται να εγκαταστήσεις τίποτα στον άλλο διακομιστή (μόνο τοπικά αν χρειαστεί).**

## **Serveo**

Από [https://serveo.net/](https://serveo.net/), επιτρέπει πολλές δυνατότητες http και προώθησης θυρών **δωρεάν**.
```bash
# Get a random port from serveo.net to expose a local port
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Από [https://www.socketxp.com/download](https://www.socketxp.com/download), επιτρέπει την έκθεση tcp και http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Από [https://ngrok.com/](https://ngrok.com/), επιτρέπει την έκθεση http και tcp θυρών:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Από [https://telebit.cloud/](https://telebit.cloud/) επιτρέπει την έκθεση http και tcp θυρών:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Από [https://localxpose.io/](https://localxpose.io/), επιτρέπει πολλές δυνατότητες http και προώθησης θυρών **χωρίς κόστος**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Από [https://expose.dev/](https://expose.dev/) επιτρέπει την έκθεση http και tcp θυρών:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Από [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) επιτρέπει την έκθεση http δωρεάν:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
