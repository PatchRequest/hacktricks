# Cheat Engine

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où des valeurs importantes sont enregistrées dans la mémoire d'un jeu en cours d'exécution et les modifier.\
Lorsque vous le téléchargez et l'exécutez, vous êtes **présenté** avec un **tutoriel** sur la façon d'utiliser l'outil. Si vous souhaitez apprendre à utiliser l'outil, il est fortement recommandé de le compléter.

## Que cherchez-vous ?

![](<../../.gitbook/assets/image (762).png>)

Cet outil est très utile pour trouver **où une certaine valeur** (généralement un nombre) **est stockée dans la mémoire** d'un programme.\
**Généralement, les nombres** sont stockés sous forme de **4 octets**, mais vous pouvez également les trouver sous des formats **double** ou **float**, ou vous pouvez vouloir chercher quelque chose **de différent d'un nombre**. Pour cette raison, vous devez vous assurer de **sélectionner** ce que vous souhaitez **chercher** :

![](<../../.gitbook/assets/image (324).png>)

Vous pouvez également indiquer **différents** types de **recherches** :

![](<../../.gitbook/assets/image (311).png>)

Vous pouvez également cocher la case pour **arrêter le jeu pendant le scan de la mémoire** :

![](<../../.gitbook/assets/image (1052).png>)

### Raccourcis

Dans _**Édition --> Paramètres --> Raccourcis**_, vous pouvez définir différents **raccourcis** pour différents objectifs, comme **arrêter** le **jeu** (ce qui est très utile si à un moment donné vous souhaitez scanner la mémoire). D'autres options sont disponibles :

![](<../../.gitbook/assets/image (864).png>)

## Modification de la valeur

Une fois que vous **avez trouvé** où se trouve la **valeur** que vous **cherchez** (plus d'informations à ce sujet dans les étapes suivantes), vous pouvez **la modifier** en double-cliquant dessus, puis en double-cliquant sur sa valeur :

![](<../../.gitbook/assets/image (563).png>)

Et enfin, **cochez la case** pour effectuer la modification dans la mémoire :

![](<../../.gitbook/assets/image (385).png>)

Le **changement** dans la **mémoire** sera immédiatement **appliqué** (notez que tant que le jeu n'utilise pas à nouveau cette valeur, la valeur **ne sera pas mise à jour dans le jeu**).

## Recherche de la valeur

Donc, nous allons supposer qu'il y a une valeur importante (comme la vie de votre utilisateur) que vous souhaitez améliorer, et vous cherchez cette valeur dans la mémoire.

### Par un changement connu

Supposons que vous cherchez la valeur 100, vous **effectuez un scan** à la recherche de cette valeur et vous trouvez beaucoup de coïncidences :

![](<../../.gitbook/assets/image (108).png>)

Ensuite, vous faites quelque chose pour que **la valeur change**, et vous **arrêtez** le jeu et **effectuez** un **scan suivant** :

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine recherchera les **valeurs** qui **sont passées de 100 à la nouvelle valeur**. Félicitations, vous **avez trouvé** l'**adresse** de la valeur que vous cherchiez, vous pouvez maintenant la modifier.\
_**Si vous avez encore plusieurs valeurs, faites quelque chose pour modifier à nouveau cette valeur, et effectuez un autre "scan suivant" pour filtrer les adresses.**_

### Valeur inconnue, changement connu

Dans le scénario où vous **ne connaissez pas la valeur** mais que vous savez **comment la faire changer** (et même la valeur du changement), vous pouvez chercher votre nombre.

Donc, commencez par effectuer un scan de type "**Valeur initiale inconnue**" :

![](<../../.gitbook/assets/image (890).png>)

Ensuite, faites changer la valeur, indiquez **comment** la **valeur** **a changé** (dans mon cas, elle a diminué de 1) et effectuez un **scan suivant** :

![](<../../.gitbook/assets/image (371).png>)

Vous serez présenté avec **toutes les valeurs qui ont été modifiées de la manière sélectionnée** :

![](<../../.gitbook/assets/image (569).png>)

Une fois que vous avez trouvé votre valeur, vous pouvez la modifier.

Notez qu'il y a un **grand nombre de changements possibles** et vous pouvez faire ces **étapes autant de fois que vous le souhaitez** pour filtrer les résultats :

![](<../../.gitbook/assets/image (574).png>)

### Adresse mémoire aléatoire - Trouver le code

Jusqu'à présent, nous avons appris à trouver une adresse stockant une valeur, mais il est très probable que lors de **différentes exécutions du jeu, cette adresse se trouve à différents endroits de la mémoire**. Alors découvrons comment toujours trouver cette adresse.

En utilisant certains des trucs mentionnés, trouvez l'adresse où votre jeu actuel stocke la valeur importante. Ensuite (en arrêtant le jeu si vous le souhaitez), faites un **clic droit** sur l'**adresse** trouvée et sélectionnez "**Découvrir ce qui accède à cette adresse**" ou "**Découvrir ce qui écrit à cette adresse**" :

![](<../../.gitbook/assets/image (1067).png>)

La **première option** est utile pour savoir quelles **parties** du **code** **utilisent** cette **adresse** (ce qui est utile pour d'autres choses comme **savoir où vous pouvez modifier le code** du jeu).\
La **deuxième option** est plus **spécifique**, et sera plus utile dans ce cas car nous sommes intéressés à savoir **d'où cette valeur est écrite**.

Une fois que vous avez sélectionné l'une de ces options, le **débogueur** sera **attaché** au programme et une nouvelle **fenêtre vide** apparaîtra. Maintenant, **jouez** au **jeu** et **modifiez** cette **valeur** (sans redémarrer le jeu). La **fenêtre** devrait être **remplie** avec les **adresses** qui **modifient** la **valeur** :

![](<../../.gitbook/assets/image (91).png>)

Maintenant que vous avez trouvé l'adresse qui modifie la valeur, vous pouvez **modifier le code à votre guise** (Cheat Engine vous permet de le modifier rapidement en NOPs) :

![](<../../.gitbook/assets/image (1057).png>)

Ainsi, vous pouvez maintenant le modifier pour que le code n'affecte pas votre nombre, ou l'affecte toujours de manière positive.

### Adresse mémoire aléatoire - Trouver le pointeur

En suivant les étapes précédentes, trouvez où se trouve la valeur qui vous intéresse. Ensuite, en utilisant "**Découvrir ce qui écrit à cette adresse**", découvrez quelle adresse écrit cette valeur et double-cliquez dessus pour obtenir la vue de désassemblage :

![](<../../.gitbook/assets/image (1039).png>)

Ensuite, effectuez un nouveau scan **à la recherche de la valeur hexadécimale entre "\[]"** (la valeur de $edx dans ce cas) :

![](<../../.gitbook/assets/image (994).png>)

(_Si plusieurs apparaissent, vous avez généralement besoin de l'adresse la plus petite_)\
Maintenant, nous avons **trouvé le pointeur qui modifiera la valeur qui nous intéresse**.

Cliquez sur "**Ajouter l'adresse manuellement**" :

![](<../../.gitbook/assets/image (990).png>)

Maintenant, cochez la case "Pointeur" et ajoutez l'adresse trouvée dans la zone de texte (dans ce scénario, l'adresse trouvée dans l'image précédente était "Tutorial-i386.exe"+2426B0) :

![](<../../.gitbook/assets/image (392).png>)

(Notez comment le premier "Adresse" est automatiquement rempli à partir de l'adresse du pointeur que vous introduisez)

Cliquez sur OK et un nouveau pointeur sera créé :

![](<../../.gitbook/assets/image (308).png>)

Maintenant, chaque fois que vous modifiez cette valeur, vous **modifiez la valeur importante même si l'adresse mémoire où se trouve la valeur est différente.**

### Injection de code

L'injection de code est une technique où vous injectez un morceau de code dans le processus cible, puis redirigez l'exécution du code pour passer par votre propre code écrit (comme vous donner des points au lieu de les retirer).

Donc, imaginez que vous avez trouvé l'adresse qui soustrait 1 à la vie de votre joueur :

![](<../../.gitbook/assets/image (203).png>)

Cliquez sur Afficher le désassembleur pour obtenir le **code désassemblé**.\
Ensuite, cliquez sur **CTRL+a** pour invoquer la fenêtre d'Auto assemble et sélectionnez _**Modèle --> Injection de code**_

![](<../../.gitbook/assets/image (902).png>)

Remplissez l'**adresse de l'instruction que vous souhaitez modifier** (cela est généralement rempli automatiquement) :

![](<../../.gitbook/assets/image (744).png>)

Un modèle sera généré :

![](<../../.gitbook/assets/image (944).png>)

Alors, insérez votre nouveau code d'assemblage dans la section "**newmem**" et retirez le code original de la section "**originalcode**" si vous ne souhaitez pas qu'il soit exécuté\*\*.\*\* Dans cet exemple, le code injecté ajoutera 2 points au lieu de soustraire 1 :

![](<../../.gitbook/assets/image (521).png>)

**Cliquez sur exécuter et ainsi de suite et votre code devrait être injecté dans le programme changeant le comportement de la fonctionnalité !**

## **Références**

* **Tutoriel Cheat Engine, complétez-le pour apprendre à commencer avec Cheat Engine**

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
