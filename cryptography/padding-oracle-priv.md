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

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


# CBC - Chaînage de blocs de chiffrement

En mode CBC, le **bloc chiffré précédent est utilisé comme IV** pour XOR avec le bloc suivant :

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Pour déchiffrer en CBC, les **opérations** **opposées** sont effectuées :

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Remarquez qu'il est nécessaire d'utiliser une **clé de chiffrement** et un **IV**.

# Remplissage de message

Comme le chiffrement est effectué en **blocs** de **taille** **fixe**, un **remplissage** est généralement nécessaire dans le **dernier** **bloc** pour compléter sa longueur.\
Généralement, **PKCS7** est utilisé, ce qui génère un remplissage **répétant** le **nombre** de **bytes** **nécessaires** pour **compléter** le bloc. Par exemple, si le dernier bloc manque de 3 bytes, le remplissage sera `\x03\x03\x03`.

Voyons plus d'exemples avec **2 blocs de longueur 8bytes** :

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Notez comment dans le dernier exemple le **dernier bloc était plein donc un autre a été généré uniquement avec du remplissage**.

# Oracle de remplissage

Lorsqu'une application déchiffre des données chiffrées, elle déchiffre d'abord les données ; puis elle supprime le remplissage. Lors du nettoyage du remplissage, si un **remplissage invalide déclenche un comportement détectable**, vous avez une **vulnérabilité d'oracle de remplissage**. Le comportement détectable peut être une **erreur**, un **manque de résultats**, ou une **réponse plus lente**.

Si vous détectez ce comportement, vous pouvez **déchiffrer les données chiffrées** et même **chiffrer n'importe quel texte clair**.

## Comment exploiter

Vous pourriez utiliser [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) pour exploiter ce type de vulnérabilité ou simplement faire
```
sudo apt-get install padbuster
```
Pour tester si le cookie d'un site est vulnérable, vous pourriez essayer :
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**L'encodage 0** signifie que **base64** est utilisé (mais d'autres sont disponibles, consultez le menu d'aide).

Vous pourriez également **exploiter cette vulnérabilité pour chiffrer de nouvelles données. Par exemple, imaginez que le contenu du cookie est "**_**user=MyUsername**_**", alors vous pouvez le changer en "\_user=administrator\_" et élever les privilèges à l'intérieur de l'application. Vous pourriez également le faire en utilisant `paduster` en spécifiant le paramètre -plaintext** :
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Si le site est vulnérable, `padbuster` essaiera automatiquement de trouver quand l'erreur de remplissage se produit, mais vous pouvez également indiquer le message d'erreur en utilisant le paramètre **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## La théorie

En **résumé**, vous pouvez commencer à déchiffrer les données chiffrées en devinant les valeurs correctes qui peuvent être utilisées pour créer tous les **différents paddings**. Ensuite, l'attaque de l'oracle de padding commencera à déchiffrer les octets de la fin au début en devinant quelle sera la valeur correcte qui **crée un padding de 1, 2, 3, etc**.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Imaginez que vous avez un texte chiffré qui occupe **2 blocs** formés par les octets de **E0 à E15**.\
Pour **décrypter** le **dernier** **bloc** (**E8** à **E15**), tout le bloc passe par le "décryptage par bloc" générant les **octets intermédiaires I0 à I15**.\
Enfin, chaque octet intermédiaire est **XORé** avec les octets chiffrés précédents (E0 à E7). Donc :

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Maintenant, il est possible de **modifier `E7` jusqu'à ce que `C15` soit `0x01`**, ce qui sera également un padding correct. Donc, dans ce cas : `\x01 = I15 ^ E'7`

Ainsi, en trouvant E'7, il est **possible de calculer I15** : `I15 = 0x01 ^ E'7`

Ce qui nous permet de **calculer C15** : `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Sachant **C15**, il est maintenant possible de **calculer C14**, mais cette fois en forçant le padding `\x02\x02`.

Ce BF est aussi complexe que le précédent car il est possible de calculer le `E''15` dont la valeur est 0x02 : `E''7 = \x02 ^ I15` donc il suffit de trouver le **`E'14`** qui génère un **`C14` égal à `0x02`**.\
Ensuite, suivez les mêmes étapes pour déchiffrer C14 : **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Suivez cette chaîne jusqu'à ce que vous déchiffriez tout le texte chiffré.**

## Détection de la vulnérabilité

Enregistrez un compte et connectez-vous avec ce compte.\
Si vous **vous connectez plusieurs fois** et obtenez toujours le **même cookie**, il y a probablement **quelque chose** **de mal** dans l'application. Le **cookie renvoyé devrait être unique** chaque fois que vous vous connectez. Si le cookie est **toujours** le **même**, il sera probablement toujours valide et il **n'y aura aucun moyen de l'invalider**.

Maintenant, si vous essayez de **modifier** le **cookie**, vous pouvez voir que vous obtenez une **erreur** de l'application.\
Mais si vous BF le padding (en utilisant padbuster par exemple), vous parvenez à obtenir un autre cookie valide pour un utilisateur différent. Ce scénario est très probablement vulnérable à padbuster.

## Références

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
