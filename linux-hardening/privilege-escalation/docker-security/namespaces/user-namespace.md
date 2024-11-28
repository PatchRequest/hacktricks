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

Un espace de noms utilisateur est une fonctionnalité du noyau Linux qui **fournit une isolation des mappages d'ID utilisateur et de groupe**, permettant à chaque espace de noms utilisateur d'avoir son **propre ensemble d'ID utilisateur et de groupe**. Cette isolation permet aux processus s'exécutant dans différents espaces de noms utilisateurs d'**avoir des privilèges et une propriété différents**, même s'ils partagent les mêmes ID utilisateur et de groupe numériquement.

Les espaces de noms utilisateurs sont particulièrement utiles dans la conteneurisation, où chaque conteneur doit avoir son propre ensemble indépendant d'ID utilisateur et de groupe, permettant une meilleure sécurité et isolation entre les conteneurs et le système hôte.

### How it works:

1. Lorsqu'un nouvel espace de noms utilisateur est créé, il **commence avec un ensemble vide de mappages d'ID utilisateur et de groupe**. Cela signifie que tout processus s'exécutant dans le nouvel espace de noms utilisateur **n'a initialement aucun privilège en dehors de l'espace de noms**.
2. Des mappages d'ID peuvent être établis entre les ID utilisateur et de groupe dans le nouvel espace de noms et ceux dans l'espace de noms parent (ou hôte). Cela **permet aux processus dans le nouvel espace de noms d'avoir des privilèges et une propriété correspondant aux ID utilisateur et de groupe dans l'espace de noms parent**. Cependant, les mappages d'ID peuvent être restreints à des plages et sous-ensembles spécifiques d'ID, permettant un contrôle précis sur les privilèges accordés aux processus dans le nouvel espace de noms.
3. Au sein d'un espace de noms utilisateur, **les processus peuvent avoir des privilèges root complets (UID 0) pour les opérations à l'intérieur de l'espace de noms**, tout en ayant des privilèges limités en dehors de l'espace de noms. Cela permet **aux conteneurs de fonctionner avec des capacités similaires à celles de root dans leur propre espace de noms sans avoir des privilèges root complets sur le système hôte**.
4. Les processus peuvent se déplacer entre les espaces de noms en utilisant l'appel système `setns()` ou créer de nouveaux espaces de noms en utilisant les appels système `unshare()` ou `clone()` avec le drapeau `CLONE_NEWUSER`. Lorsqu'un processus se déplace vers un nouvel espace de noms ou en crée un, il commencera à utiliser les mappages d'ID utilisateur et de groupe associés à cet espace de noms.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
En montant une nouvelle instance du système de fichiers `/proc` si vous utilisez le paramètre `--mount-proc`, vous vous assurez que le nouveau namespace de montage a une **vue précise et isolée des informations de processus spécifiques à ce namespace**.

<details>

<summary>Erreur : bash : fork : Impossible d'allouer de la mémoire</summary>

Lorsque `unshare` est exécuté sans l'option `-f`, une erreur est rencontrée en raison de la façon dont Linux gère les nouveaux namespaces PID (identifiant de processus). Les détails clés et la solution sont décrits ci-dessous :

1. **Explication du problème** :
- Le noyau Linux permet à un processus de créer de nouveaux namespaces en utilisant l'appel système `unshare`. Cependant, le processus qui initie la création d'un nouveau namespace PID (appelé le processus "unshare") n'entre pas dans le nouveau namespace ; seuls ses processus enfants le font.
- L'exécution de `%unshare -p /bin/bash%` démarre `/bin/bash` dans le même processus que `unshare`. Par conséquent, `/bin/bash` et ses processus enfants se trouvent dans le namespace PID d'origine.
- Le premier processus enfant de `/bin/bash` dans le nouveau namespace devient PID 1. Lorsque ce processus se termine, il déclenche le nettoyage du namespace s'il n'y a pas d'autres processus, car PID 1 a le rôle spécial d'adopter les processus orphelins. Le noyau Linux désactivera alors l'allocation de PID dans ce namespace.

2. **Conséquence** :
- La sortie de PID 1 dans un nouveau namespace entraîne le nettoyage du drapeau `PIDNS_HASH_ADDING`. Cela entraîne l'échec de la fonction `alloc_pid` à allouer un nouveau PID lors de la création d'un nouveau processus, produisant l'erreur "Impossible d'allouer de la mémoire".

3. **Solution** :
- Le problème peut être résolu en utilisant l'option `-f` avec `unshare`. Cette option permet à `unshare` de forker un nouveau processus après avoir créé le nouveau namespace PID.
- L'exécution de `%unshare -fp /bin/bash%` garantit que la commande `unshare` elle-même devient PID 1 dans le nouveau namespace. `/bin/bash` et ses processus enfants sont alors en toute sécurité contenus dans ce nouveau namespace, empêchant la sortie prématurée de PID 1 et permettant une allocation normale de PID.

En veillant à ce que `unshare` s'exécute avec le drapeau `-f`, le nouveau namespace PID est correctement maintenu, permettant à `/bin/bash` et à ses sous-processus de fonctionner sans rencontrer l'erreur d'allocation de mémoire.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Pour utiliser l'espace de noms utilisateur, le démon Docker doit être démarré avec **`--userns-remap=default`** (Dans ubuntu 14.04, cela peut être fait en modifiant `/etc/default/docker` puis en exécutant `sudo service docker restart`)

### &#x20;Vérifiez dans quel espace de noms se trouve votre processus
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Il est possible de vérifier la carte des utilisateurs depuis le conteneur docker avec :
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Ou depuis l'hôte avec :
```bash
cat /proc/<pid>/uid_map
```
### Trouver tous les espaces de noms utilisateur

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrer dans un espace de noms utilisateur
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Aussi, vous ne pouvez **entrer dans un autre espace de processus que si vous êtes root**. Et vous **ne pouvez pas** **entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/user`).

### Créer un nouvel espace de noms utilisateur (avec des mappages)

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
### Récupération des capacités

Dans le cas des espaces de noms utilisateurs, **lorsqu'un nouvel espace de noms utilisateur est créé, le processus qui entre dans l'espace de noms se voit accorder un ensemble complet de capacités au sein de cet espace de noms**. Ces capacités permettent au processus d'effectuer des opérations privilégiées telles que **le montage** **de systèmes de fichiers**, la création de périphériques ou le changement de propriété des fichiers, mais **uniquement dans le contexte de son espace de noms utilisateur**.

Par exemple, lorsque vous avez la capacité `CAP_SYS_ADMIN` au sein d'un espace de noms utilisateur, vous pouvez effectuer des opérations qui nécessitent généralement cette capacité, comme le montage de systèmes de fichiers, mais uniquement dans le contexte de votre espace de noms utilisateur. Toute opération que vous effectuez avec cette capacité n'affectera pas le système hôte ou d'autres espaces de noms.

{% hint style="warning" %}
Par conséquent, même si obtenir un nouveau processus à l'intérieur d'un nouvel espace de noms utilisateur **vous donnera toutes les capacités de retour** (CapEff: 000001ffffffffff), vous pouvez en fait **uniquement utiliser celles liées à l'espace de noms** (montage par exemple) mais pas toutes. Donc, cela en soi n'est pas suffisant pour échapper à un conteneur Docker.
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
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR au** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

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
