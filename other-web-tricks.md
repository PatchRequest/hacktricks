# Other Web Tricks

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

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Get a hacker's perspective on your web apps, network, and cloud

**重要な、悪用可能な脆弱性を見つけて報告します。** 20以上のカスタムツールを使用して攻撃面をマッピングし、特権を昇格させるセキュリティ問題を見つけ、自動化されたエクスプロイトを使用して重要な証拠を収集し、あなたの努力を説得力のある報告書に変えます。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

### Host header

バックエンドが**Host header**を信頼していくつかのアクションを実行することが何度かあります。たとえば、パスワードリセットを送信する**ドメインとしてその値を使用する**ことがあります。したがって、パスワードをリセットするためのリンクを含むメールを受け取ったとき、使用されるドメインはHost headerに入力したものです。その後、他のユーザーのパスワードリセットを要求し、ドメインをあなたが制御するものに変更して、彼らのパスワードリセットコードを盗むことができます。[WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)。

{% hint style="warning" %}
ユーザーがリセットパスワードリンクをクリックするのを待つ必要がない場合もあることに注意してください。スパムフィルターや他の中間デバイス/ボットがそれをクリックして分析するかもしれません。
{% endhint %}

### Session booleans

時々、いくつかの検証を正しく完了すると、バックエンドは**セキュリティ属性に「True」という値のブール値を追加するだけです**。その後、別のエンドポイントは、あなたがそのチェックを成功裏に通過したかどうかを知ることができます。\
しかし、もしあなたが**チェックを通過し**、セッションがそのセキュリティ属性に「True」値を付与された場合、あなたは**同じ属性に依存する他のリソースにアクセスしようとすることができます**が、あなたは**アクセス権を持っていないはずです**。[WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)。

### Register functionality

既存のユーザーとして登録を試みてください。また、同等の文字（ドット、たくさんのスペース、Unicode）を使用してみてください。

### Takeover emails

メールを登録し、確認する前にメールを変更します。次に、新しい確認メールが最初に登録されたメールに送信される場合、任意のメールを乗っ取ることができます。また、2番目のメールが最初のメールを確認することを有効にできる場合、任意のアカウントを乗っ取ることもできます。

### Access Internal servicedesk of companies using atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE method

開発者は、プロダクション環境でさまざまなデバッグオプションを無効にするのを忘れることがあります。たとえば、HTTP `TRACE`メソッドは診断目的で設計されています。これが有効になっている場合、Webサーバーは`TRACE`メソッドを使用するリクエストに対して、受信した正確なリクエストを応答にエコーします。この動作は通常無害ですが、時折、リバースプロキシによってリクエストに追加される内部認証ヘッダーの名前など、情報漏洩につながることがあります。![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Get a hacker's perspective on your web apps, network, and cloud

**重要な、悪用可能な脆弱性を見つけて報告します。** 20以上のカスタムツールを使用して攻撃面をマッピングし、特権を昇格させるセキュリティ問題を見つけ、自動化されたエクスプロイトを使用して重要な証拠を収集し、あなたの努力を説得力のある報告書に変えます。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

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
