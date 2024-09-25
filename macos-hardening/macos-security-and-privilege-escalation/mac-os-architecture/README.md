# macOS Kernel & System Extensions

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

## XNU Kernel

O **núcleo do macOS é o XNU**, que significa "X não é Unix". Este kernel é fundamentalmente composto pelo **microkernel Mach** (a ser discutido mais tarde), **e** elementos da Berkeley Software Distribution (**BSD**). O XNU também fornece uma plataforma para **drivers de kernel através de um sistema chamado I/O Kit**. O kernel XNU é parte do projeto de código aberto Darwin, o que significa que **seu código-fonte é acessível livremente**.

De uma perspectiva de um pesquisador de segurança ou um desenvolvedor Unix, **macOS** pode parecer bastante **semelhante** a um sistema **FreeBSD** com uma GUI elegante e uma série de aplicativos personalizados. A maioria dos aplicativos desenvolvidos para BSD irá compilar e rodar no macOS sem precisar de modificações, já que as ferramentas de linha de comando familiares aos usuários de Unix estão todas presentes no macOS. No entanto, como o kernel XNU incorpora Mach, existem algumas diferenças significativas entre um sistema tradicional semelhante ao Unix e o macOS, e essas diferenças podem causar problemas potenciais ou fornecer vantagens únicas.

Versão de código aberto do XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach é um **microkernel** projetado para ser **compatível com UNIX**. Um de seus princípios de design chave foi **minimizar** a quantidade de **código** executando no espaço do **kernel** e, em vez disso, permitir que muitas funções típicas do kernel, como sistema de arquivos, rede e I/O, **executem como tarefas de nível de usuário**.

No XNU, Mach é **responsável por muitas das operações críticas de baixo nível** que um kernel normalmente lida, como agendamento de processador, multitarefa e gerenciamento de memória virtual.

### BSD

O **kernel** XNU também **incorpora** uma quantidade significativa de código derivado do projeto **FreeBSD**. Este código **executa como parte do kernel junto com Mach**, no mesmo espaço de endereço. No entanto, o código FreeBSD dentro do XNU pode diferir substancialmente do código FreeBSD original porque modificações foram necessárias para garantir sua compatibilidade com Mach. FreeBSD contribui para muitas operações do kernel, incluindo:

* Gerenciamento de processos
* Manipulação de sinais
* Mecanismos básicos de segurança, incluindo gerenciamento de usuários e grupos
* Infraestrutura de chamadas de sistema
* Pilha TCP/IP e sockets
* Firewall e filtragem de pacotes

Entender a interação entre BSD e Mach pode ser complexo, devido aos seus diferentes frameworks conceituais. Por exemplo, o BSD usa processos como sua unidade fundamental de execução, enquanto Mach opera com base em threads. Essa discrepância é reconciliada no XNU **associando cada processo BSD a uma tarefa Mach** que contém exatamente uma thread Mach. Quando a chamada de sistema fork() do BSD é usada, o código BSD dentro do kernel usa funções Mach para criar uma estrutura de tarefa e thread.

Além disso, **Mach e BSD mantêm cada um modelos de segurança diferentes**: o modelo de segurança de **Mach** é baseado em **direitos de porta**, enquanto o modelo de segurança do BSD opera com base em **propriedade de processos**. Disparidades entre esses dois modelos ocasionalmente resultaram em vulnerabilidades de escalonamento de privilégios locais. Além das chamadas de sistema típicas, também existem **traps Mach que permitem que programas de espaço de usuário interajam com o kernel**. Esses diferentes elementos juntos formam a arquitetura híbrida multifacetada do kernel do macOS.

### I/O Kit - Drivers

O I/O Kit é um framework de **driver de dispositivo** orientado a objetos de código aberto no kernel XNU, que lida com **drivers de dispositivo carregados dinamicamente**. Ele permite que código modular seja adicionado ao kernel em tempo real, suportando hardware diversificado.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Comunicação entre Processos

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

## macOS Kernel Extensions

macOS é **super restritivo para carregar Extensões de Kernel** (.kext) devido aos altos privilégios com que o código será executado. Na verdade, por padrão, é virtualmente impossível (a menos que um bypass seja encontrado).

Na página seguinte, você também pode ver como recuperar o `.kext` que o macOS carrega dentro de seu **kernelcache**:

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS System Extensions

Em vez de usar Extensões de Kernel, o macOS criou as Extensões de Sistema, que oferecem APIs de nível de usuário para interagir com o kernel. Dessa forma, os desenvolvedores podem evitar o uso de extensões de kernel.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referências

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
