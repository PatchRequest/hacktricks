# macOS Security Protections

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Gatekeeper

Gatekeeper é geralmente usado para se referir à combinação de **Quarantine + Gatekeeper + XProtect**, 3 módulos de segurança do macOS que tentarão **impedir os usuários de executar software potencialmente malicioso baixado**.

Mais informações em:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Processes Limitants

### MACF



### SIP - System Integrity Protection

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

O Sandbox do macOS **limita as aplicações** que estão rodando dentro do sandbox às **ações permitidas especificadas no perfil do Sandbox** com o qual o aplicativo está rodando. Isso ajuda a garantir que **a aplicação acessará apenas os recursos esperados**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparência, Consentimento e Controle)** é uma estrutura de segurança. É projetada para **gerenciar as permissões** das aplicações, especificamente regulando seu acesso a recursos sensíveis. Isso inclui elementos como **serviços de localização, contatos, fotos, microfone, câmera, acessibilidade e acesso total ao disco**. O TCC garante que os aplicativos só possam acessar esses recursos após obter o consentimento explícito do usuário, reforçando assim a privacidade e o controle sobre os dados pessoais.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Launch/Environment Constraints & Trust Cache

As restrições de lançamento no macOS são um recurso de segurança para **regulamentar a iniciação de processos** definindo **quem pode iniciar** um processo, **como** e **de onde**. Introduzidas no macOS Ventura, elas categorizam binários do sistema em categorias de restrição dentro de um **cache de confiança**. Cada binário executável tem **regras** definidas para seu **lançamento**, incluindo **auto**, **pai** e **responsável**. Estendidas a aplicativos de terceiros como **Environment** Constraints no macOS Sonoma, esses recursos ajudam a mitigar potenciais explorações do sistema ao governar as condições de lançamento de processos.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Malware Removal Tool

A Ferramenta de Remoção de Malware (MRT) é outra parte da infraestrutura de segurança do macOS. Como o nome sugere, a principal função do MRT é **remover malware conhecido de sistemas infectados**.

Uma vez que o malware é detectado em um Mac (seja pelo XProtect ou por outros meios), o MRT pode ser usado para **remover automaticamente o malware**. O MRT opera silenciosamente em segundo plano e normalmente é executado sempre que o sistema é atualizado ou quando uma nova definição de malware é baixada (parece que as regras que o MRT tem para detectar malware estão dentro do binário).

Enquanto o XProtect e o MRT são parte das medidas de segurança do macOS, eles desempenham funções diferentes:

* **XProtect** é uma ferramenta preventiva. Ele **verifica arquivos à medida que são baixados** (por meio de certos aplicativos) e, se detectar qualquer tipo conhecido de malware, **impede que o arquivo seja aberto**, evitando assim que o malware infecte seu sistema em primeiro lugar.
* **MRT**, por outro lado, é uma **ferramenta reativa**. Ele opera após o malware ter sido detectado em um sistema, com o objetivo de remover o software ofensivo para limpar o sistema.

O aplicativo MRT está localizado em **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** agora **alerta** toda vez que uma ferramenta usa uma técnica bem conhecida para persistir a execução de código (como Itens de Login, Daemons...), para que o usuário saiba melhor **qual software está persistindo**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Isso é executado com um **daemon** localizado em `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` e o **agente** em `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

A maneira como **`backgroundtaskmanagementd`** sabe que algo está instalado em uma pasta persistente é **obtendo os FSEvents** e criando alguns **handlers** para esses.

Além disso, há um arquivo plist que contém **aplicativos bem conhecidos** que frequentemente persistem, mantido pela Apple, localizado em: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeração

É possível **enumerar todos** os itens de fundo configurados executando a ferramenta cli da Apple:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Além disso, também é possível listar essas informações com [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Esta informação está sendo armazenada em **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** e o Terminal precisa de FDA.

### Brincando com BTM

Quando uma nova persistência é encontrada, um evento do tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** é gerado. Portanto, qualquer forma de **prevenir** que este **evento** seja enviado ou que o **agente alerte** o usuário ajudará um atacante a _**contornar**_ o BTM.

* **Redefinindo o banco de dados**: Executar o seguinte comando irá redefinir o banco de dados (deve reconstruí-lo do zero), no entanto, por algum motivo, após executar isso, **nenhuma nova persistência será alertada até que o sistema seja reiniciado**.
* **root** é necessário.
```bash
# Reset the database
sfltool resettbtm
```
* **Parar o Agente**: É possível enviar um sinal de parada para o agente para que ele **não avise o usuário** quando novas detecções forem encontradas.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Bug**: Se o **processo que criou a persistência existir rapidamente logo após ele**, o daemon tentará **obter informações** sobre isso, **falhará** e **não conseguirá enviar o evento** indicando que uma nova coisa está persistindo.

Referências e **mais informações sobre BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
