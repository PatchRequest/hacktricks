# PsExec/Winexec/ScExec

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) pour construire et **automatiser des workflows** facilement grâce aux **outils communautaires les plus avancés** au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Comment ils fonctionnent

Le processus est décrit dans les étapes ci-dessous, illustrant comment les binaires de service sont manipulés pour obtenir une exécution à distance sur une machine cible via SMB :

1. **La copie d'un binaire de service sur le partage ADMIN$ via SMB** est effectuée.
2. **La création d'un service sur la machine distante** est réalisée en pointant vers le binaire.
3. Le service est **démarré à distance**.
4. À la sortie, le service est **arrêté et le binaire est supprimé**.

### **Processus d'exécution manuelle de PsExec**

En supposant qu'il existe un payload exécutable (créé avec msfvenom et obfusqué à l'aide de Veil pour échapper à la détection antivirus), nommé 'met8888.exe', représentant un payload meterpreter reverse_http, les étapes suivantes sont suivies :

- **Copie du binaire** : L'exécutable est copié sur le partage ADMIN$ depuis une invite de commande, bien qu'il puisse être placé n'importe où sur le système de fichiers pour rester dissimulé.

- **Création d'un service** : En utilisant la commande Windows `sc`, qui permet de requêter, créer et supprimer des services Windows à distance, un service nommé "meterpreter" est créé pour pointer vers le binaire téléchargé.

- **Démarrage du service** : La dernière étape consiste à démarrer le service, ce qui entraînera probablement une erreur de "délai d'attente" en raison du fait que le binaire n'est pas un véritable binaire de service et échoue à renvoyer le code de réponse attendu. Cette erreur est sans conséquence car l'objectif principal est l'exécution du binaire.

L'observation de l'auditeur Metasploit révélera que la session a été initiée avec succès.

[En savoir plus sur la commande `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Trouvez des étapes plus détaillées dans : [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Vous pouvez également utiliser le binaire PsExec.exe de Windows Sysinternals :**

![](<../../.gitbook/assets/image (165).png>)

Vous pouvez également utiliser [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) pour créer et **automatiser des workflows** facilement grâce aux **outils communautaires les plus avancés** au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
