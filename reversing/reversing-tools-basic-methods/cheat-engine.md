# Cheat Engine

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes são salvos dentro da memória de um jogo em execução e alterá-los.\
Quando você baixa e executa, você é **apresentado** a um **tutorial** de como usar a ferramenta. Se você quiser aprender a usar a ferramenta, é altamente recomendado completá-lo.

## O que você está procurando?

![](<../../.gitbook/assets/image (762).png>)

Esta ferramenta é muito útil para encontrar **onde algum valor** (geralmente um número) **está armazenado na memória** de um programa.\
**Geralmente números** são armazenados em **4bytes**, mas você também pode encontrá-los em formatos **double** ou **float**, ou pode querer procurar algo **diferente de um número**. Por essa razão, você precisa ter certeza de que **seleciona** o que deseja **procurar**:

![](<../../.gitbook/assets/image (324).png>)

Você também pode indicar **diferentes** tipos de **buscas**:

![](<../../.gitbook/assets/image (311).png>)

Você também pode marcar a caixa para **parar o jogo enquanto escaneia a memória**:

![](<../../.gitbook/assets/image (1052).png>)

### Teclas de atalho

Em _**Editar --> Configurações --> Teclas de atalho**_ você pode definir diferentes **teclas de atalho** para diferentes propósitos, como **parar** o **jogo** (o que é bastante útil se em algum momento você quiser escanear a memória). Outras opções estão disponíveis:

![](<../../.gitbook/assets/image (864).png>)

## Modificando o valor

Uma vez que você **encontrou** onde está o **valor** que você está **procurando** (mais sobre isso nos próximos passos), você pode **modificá-lo** clicando duas vezes nele, e depois clicando duas vezes em seu valor:

![](<../../.gitbook/assets/image (563).png>)

E finalmente **marcando a caixa** para que a modificação seja feita na memória:

![](<../../.gitbook/assets/image (385).png>)

A **mudança** na **memória** será imediatamente **aplicada** (note que até o jogo não usar esse valor novamente, o valor **não será atualizado no jogo**).

## Buscando o valor

Então, vamos supor que há um valor importante (como a vida do seu usuário) que você deseja melhorar, e você está procurando por esse valor na memória)

### Através de uma mudança conhecida

Supondo que você está procurando o valor 100, você **realiza uma varredura** procurando por esse valor e encontra muitas coincidências:

![](<../../.gitbook/assets/image (108).png>)

Então, você faz algo para que **o valor mude**, e você **para** o jogo e **realiza** uma **próxima varredura**:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine irá procurar os **valores** que **foram de 100 para o novo valor**. Parabéns, você **encontrou** o **endereço** do valor que estava procurando, agora você pode modificá-lo.\
&#xNAN;_Se você ainda tiver vários valores, faça algo para modificar novamente esse valor e realize outra "próxima varredura" para filtrar os endereços._

### Valor desconhecido, mudança conhecida

No cenário em que você **não sabe o valor** mas sabe **como fazê-lo mudar** (e até mesmo o valor da mudança), você pode procurar seu número.

Então, comece realizando uma varredura do tipo "**Valor inicial desconhecido**":

![](<../../.gitbook/assets/image (890).png>)

Depois, faça o valor mudar, indique **como** o **valor** **mudou** (no meu caso, foi diminuído em 1) e realize uma **próxima varredura**:

![](<../../.gitbook/assets/image (371).png>)

Você será apresentado a **todos os valores que foram modificados da maneira selecionada**:

![](<../../.gitbook/assets/image (569).png>)

Uma vez que você tenha encontrado seu valor, você pode modificá-lo.

Note que há uma **muita mudança possível** e você pode fazer esses **passos quantas vezes quiser** para filtrar os resultados:

![](<../../.gitbook/assets/image (574).png>)

### Endereço de memória aleatório - Encontrando o código

Até agora aprendemos como encontrar um endereço que armazena um valor, mas é altamente provável que em **execuções diferentes do jogo esse endereço esteja em lugares diferentes da memória**. Então, vamos descobrir como sempre encontrar esse endereço.

Usando alguns dos truques mencionados, encontre o endereço onde seu jogo atual está armazenando o valor importante. Então (parando o jogo se desejar) clique com o botão direito no **endereço** encontrado e selecione "**Descobrir o que acessa esse endereço**" ou "**Descobrir o que escreve para esse endereço**":

![](<../../.gitbook/assets/image (1067).png>)

A **primeira opção** é útil para saber quais **partes** do **código** estão **usando** esse **endereço** (o que é útil para mais coisas, como **saber onde você pode modificar o código** do jogo).\
A **segunda opção** é mais **específica**, e será mais útil neste caso, pois estamos interessados em saber **de onde esse valor está sendo escrito**.

Uma vez que você tenha selecionado uma dessas opções, o **debugger** será **anexado** ao programa e uma nova **janela vazia** aparecerá. Agora, **jogue** o **jogo** e **modifique** esse **valor** (sem reiniciar o jogo). A **janela** deve ser **preenchida** com os **endereços** que estão **modificando** o **valor**:

![](<../../.gitbook/assets/image (91).png>)

Agora que você encontrou o endereço que está modificando o valor, você pode **modificar o código à sua vontade** (Cheat Engine permite que você o modifique para NOPs rapidamente):

![](<../../.gitbook/assets/image (1057).png>)

Assim, você pode agora modificá-lo para que o código não afete seu número, ou sempre afete de uma maneira positiva.

### Endereço de memória aleatório - Encontrando o ponteiro

Seguindo os passos anteriores, encontre onde o valor que você está interessado está. Então, usando "**Descobrir o que escreve para esse endereço**", descubra qual endereço escreve esse valor e clique duas vezes nele para obter a visualização da desassemblagem:

![](<../../.gitbook/assets/image (1039).png>)

Depois, realize uma nova varredura **procurando o valor hex entre "\[]"** (o valor de $edx neste caso):

![](<../../.gitbook/assets/image (994).png>)

(_Se vários aparecerem, você geralmente precisa do menor endereço_)\
Agora, encontramos o **ponteiro que estará modificando o valor que nos interessa**.

Clique em "**Adicionar Endereço Manualmente**":

![](<../../.gitbook/assets/image (990).png>)

Agora, clique na caixa de seleção "Ponteiro" e adicione o endereço encontrado na caixa de texto (neste cenário, o endereço encontrado na imagem anterior foi "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (392).png>)

(Note como o primeiro "Endereço" é automaticamente preenchido a partir do endereço do ponteiro que você introduz)

Clique em OK e um novo ponteiro será criado:

![](<../../.gitbook/assets/image (308).png>)

Agora, toda vez que você modificar esse valor, você estará **modificando o valor importante, mesmo que o endereço de memória onde o valor está seja diferente.**

### Injeção de Código

A injeção de código é uma técnica onde você injeta um pedaço de código no processo alvo e, em seguida, redireciona a execução do código para passar pelo seu próprio código escrito (como te dar pontos em vez de subtraí-los).

Então, imagine que você encontrou o endereço que está subtraindo 1 da vida do seu jogador:

![](<../../.gitbook/assets/image (203).png>)

Clique em Mostrar desassemblador para obter o **código desassemblado**.\
Depois, clique **CTRL+a** para invocar a janela de Auto assemble e selecione _**Modelo --> Injeção de Código**_

![](<../../.gitbook/assets/image (902).png>)

Preencha o **endereço da instrução que você deseja modificar** (isso geralmente é preenchido automaticamente):

![](<../../.gitbook/assets/image (744).png>)

Um modelo será gerado:

![](<../../.gitbook/assets/image (944).png>)

Então, insira seu novo código assembly na seção "**newmem**" e remova o código original da seção "**originalcode**" se você não quiser que ele seja executado\*\*.\*\* Neste exemplo, o código injetado adicionará 2 pontos em vez de subtrair 1:

![](<../../.gitbook/assets/image (521).png>)

**Clique em executar e assim por diante e seu código deve ser injetado no programa mudando o comportamento da funcionalidade!**

## **Referências**

* **Tutorial do Cheat Engine, complete-o para aprender como começar com o Cheat Engine** 

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
