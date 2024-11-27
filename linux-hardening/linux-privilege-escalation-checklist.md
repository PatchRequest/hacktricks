# チェックリスト - Linux特権昇格

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取りましょう！

**ハッキングインサイト**\
ハッキングのスリルと課題に深く掘り下げたコンテンツに参加してください

**リアルタイムハックニュース**\
リアルタイムのニュースとインサイトを通じて、急速に変化するハッキングの世界に遅れずについていきましょう

**最新のお知らせ**\
新しいバグバウンティの開始や重要なプラットフォームの更新について情報を得てください

**[**Discord**](https://discord.com/invite/N3FrSbmwdy)に参加して、今日からトップハッカーとコラボレーションを始めましょう！**

### **Linuxローカル特権昇格ベクトルを探すための最良のツール：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [システム情報](privilege-escalation/#system-information)

* [ ] **OS情報**を取得
* [ ] [**PATH**](privilege-escalation/#path)を確認し、**書き込み可能なフォルダー**はありますか？
* [ ] [**env変数**](privilege-escalation/#env-info)を確認し、機密情報はありますか？
* [ ] [**カーネルエクスプロイト**](privilege-escalation/#kernel-exploits)を**スクリプトを使用して**検索（DirtyCow？）
* [ ] [**sudoバージョン**が脆弱かどうかを確認](privilege-escalation/#sudo-version)
* [ ] [**Dmesg**署名検証に失敗しました](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] さらなるシステム列挙（[日付、システム統計、CPU情報、プリンター](privilege-escalation/#more-system-enumeration)）
* [ ] [さらなる防御を列挙](privilege-escalation/#enumerate-possible-defenses)

### [ドライブ](privilege-escalation/#drives)

* [ ] **マウントされた**ドライブをリスト
* [ ] **アンマウントされたドライブはありますか？**
* [ ] **fstabにクレデンシャルはありますか？**

### [**インストールされたソフトウェア**](privilege-escalation/#installed-software)

* [ ] **インストールされた**[ **便利なソフトウェア**](privilege-escalation/#useful-software)を確認
* [ ] **インストールされた**[ **脆弱なソフトウェア**](privilege-escalation/#vulnerable-software-installed)を確認

### [プロセス](privilege-escalation/#processes)

* [ ] **不明なソフトウェアが実行されていますか？**
* [ ] **必要以上の特権で実行されているソフトウェアはありますか？**
* [ ] **実行中のプロセスのエクスプロイトを検索**（特に実行中のバージョン）。
* [ ] **実行中のプロセスのバイナリを変更できますか？**
* [ ] **プロセスを監視**し、興味深いプロセスが頻繁に実行されているか確認します。
* [ ] **興味深いプロセスメモリを**（パスワードが保存されている可能性がある場所）**読み取ることができますか？**

### [スケジュールされた/cronジョブ？](privilege-escalation/#scheduled-jobs)

* [ ] [**PATH**](privilege-escalation/#cron-path)がcronによって変更されており、**書き込み**できるか？
* [ ] cronジョブに[**ワイルドカード**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)はありますか？
* [ ] **変更可能なスクリプト**（[**cronスクリプトの上書きとシンボリックリンク**](privilege-escalation/#cron-script-overwriting-and-symlink)）が**実行されている**か、**変更可能なフォルダー**内にありますか？
* [ ] **スクリプトが非常に頻繁に実行されている**ことを検出しましたか？（1、2、または5分ごと）

### [サービス](privilege-escalation/#services)

* [ ] **書き込み可能な.service**ファイルはありますか？
* [ ] **サービスによって実行される書き込み可能なバイナリ**はありますか？
* [ ] **systemd PATH内の書き込み可能なフォルダー**はありますか？

### [タイマー](privilege-escalation/#timers)

* [ ] **書き込み可能なタイマー**はありますか？

### [ソケット](privilege-escalation/#sockets)

* [ ] **書き込み可能な.socket**ファイルはありますか？
* [ ] **任意のソケットと通信できますか？**
* [ ] **興味深い情報を持つHTTPソケット**はありますか？

### [D-Bus](privilege-escalation/#d-bus)

* [ ] **任意のD-Busと通信できますか？**

### [ネットワーク](privilege-escalation/#network)

* [ ] ネットワークを列挙して、どこにいるかを知る
* [ ] **シェルを取得する前にアクセスできなかったオープンポートはありますか？**
* [ ] `tcpdump`を使用して**トラフィックをスニッフィング**できますか？

### [ユーザー](privilege-escalation/#users)

* [ ] 一般的なユーザー/グループの**列挙**
* [ ] **非常に大きなUID**を持っていますか？ **マシンは脆弱ですか？**
* あなたが属する[**グループのおかげで特権を昇格できますか？**](privilege-escalation/interesting-groups-linux-pe/)
* [ ] **クリップボード**データは？
* [ ] パスワードポリシーは？
* **以前に発見したすべての**[**既知のパスワードを使用して、各**ユーザー**でログインを試みてください。パスワードなしでのログインも試みてください。**

### [書き込み可能なPATH](privilege-escalation/#writable-path-abuses)

* [ ] **PATH内のフォルダーに書き込み権限がある場合、特権を昇格できる可能性があります。**

### [SUDOおよびSUIDコマンド](privilege-escalation/#sudo-and-suid)

* [ ] **sudoで任意のコマンドを実行できますか？** rootとして何かをREAD、WRITE、またはEXECUTEできますか？（[**GTFOBins**](https://gtfobins.github.io)）
* [ ] **エクスプロイト可能なSUIDバイナリはありますか？**（[**GTFOBins**](https://gtfobins.github.io)）
* [ ] [**sudoコマンドは**パスによって**制限されていますか？制限を**バイパス**できますか？](privilege-escalation/#sudo-execution-bypassing-paths)
* [ ] [**パスが指定されていないSudo/SUIDバイナリ**](privilege-escalation/#sudo-command-suid-binary-without-command-path)はありますか？
* [ ] [**パスを指定したSUIDバイナリ**](privilege-escalation/#suid-binary-with-command-path)？ バイパス
* [ ] [**LD\_PRELOAD脆弱性**](privilege-escalation/#ld_preload)
* [ ] **書き込み可能なフォルダーからのSUIDバイナリにおける**[**.soライブラリの欠如**](privilege-escalation/#suid-binary-so-injection)はありますか？
* [ ] [**SUDOトークンが利用可能**](privilege-escalation/#reusing-sudo-tokens)ですか？ [**SUDOトークンを作成できますか？**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)
* [ ] [**sudoersファイルを読み取るまたは変更できますか？**](privilege-escalation/#etc-sudoers-etc-sudoers-d)
* [ ] [**/etc/ld.so.conf.d/**を**変更できますか？**](privilege-escalation/#etc-ld-so-conf-d)
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas)コマンド

### [能力](privilege-escalation/#capabilities)

* [ ] いずれかのバイナリに**予期しない能力**がありますか？

### [ACL](privilege-escalation/#acls)

* [ ] いずれかのファイルに**予期しないACL**がありますか？

### [オープンシェルセッション](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL予測可能PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSHの興味深い設定値**](privilege-escalation/#ssh-interesting-configuration-values)

### [興味深いファイル](privilege-escalation/#interesting-files)

* [ ] **プロファイルファイル** - 機密データを読み取る？ プライバシー昇格のために書き込む？
* [ ] **passwd/shadowファイル** - 機密データを読み取る？ プライバシー昇格のために書き込む？
* [ ] 機密データのために**一般的に興味深いフォルダーを確認**
* [ ] **奇妙な場所/所有ファイル、**アクセスできるか、実行可能ファイルを変更できるかもしれません
* [ ] **最近の分で変更された**
* [ ] **Sqlite DBファイル**
* [ ] **隠しファイル**
* [ ] **PATH内のスクリプト/バイナリ**
* [ ] **Webファイル**（パスワード？）
* [ ] **バックアップ**？
* [ ] **パスワードを含む既知のファイル**：**Linpeas**と**LaZagne**を使用
* [ ] **一般的な検索**

### [**書き込み可能なファイル**](privilege-escalation/#writable-files)

* [ ] **任意のコマンドを実行するためにpythonライブラリを変更できますか？**
* [ ] **ログファイルを変更できますか？** **Logtotten**エクスプロイト
* [ ] **/etc/sysconfig/network-scripts/**を変更できますか？ Centos/Redhatエクスプロイト
* [ ] [**ini、int.d、systemdまたはrc.dファイルに書き込むことができますか？**](privilege-escalation/#init-init-d-systemd-and-rc-d)

### [**その他のトリック**](privilege-escalation/#other-tricks)

* [ ] [**NFSを悪用して特権を昇格できますか？**](privilege-escalation/#nfs-privilege-escalation)
* [ ] **制限されたシェルから脱出する必要がありますか？** [**](privilege-escalation/#escaping-from-restricted-shells)

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取りましょう！

**ハッキングインサイト**\
ハッキングのスリルと課題に深く掘り下げたコンテンツに参加してください

**リアルタイムハックニュース**\
リアルタイムのニュースとインサイトを通じて、急速に変化するハッキングの世界に遅れずについていきましょう

**最新のお知らせ**\
新しいバグバウンティの開始や重要なプラットフォームの更新について情報を得てください

**[**Discord**](https://discord.com/invite/N3FrSbmwdy)に参加して、今日からトップハッカーとコラボレーションを始めましょう！**

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
