# Outras Dicas da Web

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenha a perspectiva de um hacker sobre seus aplicativos web, rede e nuvem**

**Encontre e relate vulnerabilidades críticas e exploráveis com impacto real nos negócios.** Use nossas mais de 20 ferramentas personalizadas para mapear a superfície de ataque, encontrar problemas de segurança que permitem que você eleve privilégios e use exploits automatizados para coletar evidências essenciais, transformando seu trabalho árduo em relatórios persuasivos.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

### Cabeçalho Host

Várias vezes o back-end confia no **cabeçalho Host** para realizar algumas ações. Por exemplo, ele pode usar seu valor como o **domínio para enviar um reset de senha**. Assim, quando você recebe um e-mail com um link para redefinir sua senha, o domínio utilizado é aquele que você colocou no cabeçalho Host. Então, você pode solicitar o reset de senha de outros usuários e mudar o domínio para um controlado por você para roubar seus códigos de reset de senha. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Note que é possível que você não precise nem esperar o usuário clicar no link de redefinição de senha para obter o token, pois talvez até mesmo **filtros de spam ou outros dispositivos/bots intermediários cliquem nele para analisá-lo**.
{% endhint %}

### Booleanos de sessão

Às vezes, quando você completa alguma verificação corretamente, o back-end **apenas adiciona um booleano com o valor "True" a um atributo de segurança da sua sessão**. Então, um endpoint diferente saberá se você passou com sucesso naquela verificação.\
No entanto, se você **passar a verificação** e sua sessão receber esse valor "True" no atributo de segurança, você pode tentar **acessar outros recursos** que **dependem do mesmo atributo** mas que você **não deveria ter permissões** para acessar. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funcionalidade de registro

Tente se registrar como um usuário já existente. Tente também usar caracteres equivalentes (pontos, muitos espaços e Unicode).

### Tomar conta de e-mails

Registre um e-mail, antes de confirmá-lo, mude o e-mail, então, se o novo e-mail de confirmação for enviado para o primeiro e-mail registrado, você pode tomar conta de qualquer e-mail. Ou se você puder habilitar o segundo e-mail confirmando o primeiro, você também pode tomar conta de qualquer conta.

### Acessar o serviço de atendimento interno de empresas usando Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Método TRACE

Os desenvolvedores podem esquecer de desativar várias opções de depuração no ambiente de produção. Por exemplo, o método HTTP `TRACE` é projetado para fins de diagnóstico. Se habilitado, o servidor web responderá a solicitações que usam o método `TRACE` ecoando na resposta a exata solicitação que foi recebida. Esse comportamento é frequentemente inofensivo, mas ocasionalmente leva à divulgação de informações, como o nome de cabeçalhos de autenticação internos que podem ser anexados a solicitações por proxies reversos.![Imagem para o post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Imagem para o post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenha a perspectiva de um hacker sobre seus aplicativos web, rede e nuvem**

**Encontre e relate vulnerabilidades críticas e exploráveis com impacto real nos negócios.** Use nossas mais de 20 ferramentas personalizadas para mapear a superfície de ataque, encontrar problemas de segurança que permitem que você eleve privilégios e use exploits automatizados para coletar evidências essenciais, transformando seu trabalho árduo em relatórios persuasivos.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
