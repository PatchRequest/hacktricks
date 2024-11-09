# Autres astuces Web

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Obtenez la perspective d'un hacker sur vos applications web, réseau et cloud

**Trouvez et signalez des vulnérabilités critiques et exploitables ayant un impact commercial réel.** Utilisez nos 20+ outils personnalisés pour cartographier la surface d'attaque, trouver des problèmes de sécurité qui vous permettent d'escalader les privilèges, et utilisez des exploits automatisés pour collecter des preuves essentielles, transformant votre travail acharné en rapports convaincants.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

### En-tête d'hôte

Plusieurs fois, le back-end fait confiance à l'**en-tête d'hôte** pour effectuer certaines actions. Par exemple, il pourrait utiliser sa valeur comme **domaine pour envoyer une réinitialisation de mot de passe**. Donc, lorsque vous recevez un e-mail avec un lien pour réinitialiser votre mot de passe, le domaine utilisé est celui que vous avez mis dans l'en-tête d'hôte. Ensuite, vous pouvez demander la réinitialisation du mot de passe d'autres utilisateurs et changer le domaine pour un contrôlé par vous afin de voler leurs codes de réinitialisation de mot de passe. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Notez qu'il est possible que vous n'ayez même pas besoin d'attendre que l'utilisateur clique sur le lien de réinitialisation du mot de passe pour obtenir le jeton, car peut-être même **les filtres anti-spam ou d'autres dispositifs/bots intermédiaires cliqueront dessus pour l'analyser**.
{% endhint %}

### Booléens de session

Parfois, lorsque vous complétez une vérification correctement, le back-end **ajoute simplement un booléen avec la valeur "True" à un attribut de sécurité de votre session**. Ensuite, un point de terminaison différent saura si vous avez réussi à passer cette vérification.\
Cependant, si vous **passez la vérification** et que votre session se voit attribuer cette valeur "True" dans l'attribut de sécurité, vous pouvez essayer d'**accéder à d'autres ressources** qui **dépendent du même attribut** mais auxquelles vous **ne devriez pas avoir accès**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Fonctionnalité d'enregistrement

Essayez de vous enregistrer en tant qu'utilisateur déjà existant. Essayez également d'utiliser des caractères équivalents (points, beaucoup d'espaces et Unicode).

### Prise de contrôle des e-mails

Enregistrez un e-mail, avant de le confirmer, changez l'e-mail, puis, si le nouvel e-mail de confirmation est envoyé au premier e-mail enregistré, vous pouvez prendre le contrôle de n'importe quel e-mail. Ou si vous pouvez activer le deuxième e-mail confirmant le premier, vous pouvez également prendre le contrôle de n'importe quel compte.

### Accéder au service desk interne des entreprises utilisant Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Méthode TRACE

Les développeurs peuvent oublier de désactiver diverses options de débogage dans l'environnement de production. Par exemple, la méthode HTTP `TRACE` est conçue à des fins de diagnostic. Si elle est activée, le serveur web répondra aux requêtes utilisant la méthode `TRACE` en écho dans la réponse la requête exacte qui a été reçue. Ce comportement est souvent inoffensif, mais peut parfois conduire à une divulgation d'informations, comme le nom des en-têtes d'authentification internes qui peuvent être ajoutés aux requêtes par des proxies inverses.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Obtenez la perspective d'un hacker sur vos applications web, réseau et cloud

**Trouvez et signalez des vulnérabilités critiques et exploitables ayant un impact commercial réel.** Utilisez nos 20+ outils personnalisés pour cartographier la surface d'attaque, trouver des problèmes de sécurité qui vous permettent d'escalader les privilèges, et utilisez des exploits automatisés pour collecter des preuves essentielles, transformant votre travail acharné en rapports convaincants.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
