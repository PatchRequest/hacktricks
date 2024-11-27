# Cheat Engine

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のゲームのメモリ内に重要な値がどこに保存されているかを見つけて変更するための便利なプログラムです。\
ダウンロードして実行すると、ツールの使い方の**チュートリアル**が**表示**されます。ツールの使い方を学びたい場合は、これを完了することを強くお勧めします。

## 何を検索していますか？

![](<../../.gitbook/assets/image (762).png>)

このツールは、プログラムのメモリ内に**どこにある値**（通常は数値）が保存されているかを見つけるのに非常に便利です。\
**通常、数値**は**4バイト**形式で保存されますが、**ダブル**や**フロート**形式で見つけることもできますし、**数値以外の何か**を探すこともあるかもしれません。そのため、**検索したいものを選択**することを確認する必要があります：

![](<../../.gitbook/assets/image (324).png>)

また、**異なる**タイプの**検索**を指定することもできます：

![](<../../.gitbook/assets/image (311).png>)

メモリをスキャンしている間に**ゲームを停止する**ためのチェックボックスをオンにすることもできます：

![](<../../.gitbook/assets/image (1052).png>)

### ホットキー

_**Edit --> Settings --> Hotkeys**_ では、**ゲームを停止する**などの目的のために異なる**ホットキー**を設定できます（これは、メモリをスキャンしたい場合に非常に便利です）。他のオプションも利用可能です：

![](<../../.gitbook/assets/image (864).png>)

## 値の変更

**探している値**がどこにあるかを**見つけたら**（このことについては次のステップで詳しく説明します）、それを**ダブルクリック**して、次にその値をダブルクリックすることで**変更**できます：

![](<../../.gitbook/assets/image (563).png>)

最後に、メモリ内で変更を行うために**チェックを入れる**：

![](<../../.gitbook/assets/image (385).png>)

**メモリ**への**変更**はすぐに**適用**されます（ゲームがこの値を再度使用するまで、値は**ゲーム内で更新されません**）。

## 値の検索

では、重要な値（ユーザーのライフなど）を改善したいと仮定し、その値をメモリ内で探しているとします。

### 既知の変更による検索

値100を探していると仮定し、その値を検索するために**スキャンを実行**すると、多くの一致が見つかります：

![](<../../.gitbook/assets/image (108).png>)

次に、**値が変更される**ようなことを行い、ゲームを**停止**して**次のスキャンを実行**します：

![](<../../.gitbook/assets/image (684).png>)

Cheat Engineは、**100から新しい値に変わった**値を検索します。おめでとうございます、探していた**アドレス**を**見つけました**。これで、値を変更できます。\
&#xNAN;_まだいくつかの値がある場合は、その値を再度変更するために何かを行い、もう一度「次のスキャン」を実行してアドレスをフィルタリングします。_

### 不明な値、既知の変更

値が**わからない**が、**どのように変更されるか**（変更の値も含む）を知っている場合は、数値を探すことができます。

まず、**不明な初期値**のタイプのスキャンを実行します：

![](<../../.gitbook/assets/image (890).png>)

次に、値を変更し、**どのように**その**値が変更されたか**を示し（私の場合は1減少しました）、**次のスキャンを実行**します：

![](<../../.gitbook/assets/image (371).png>)

選択した方法で**変更されたすべての値**が表示されます：

![](<../../.gitbook/assets/image (569).png>)

値を見つけたら、それを変更できます。

**結果をフィルタリングするために、たくさんの可能な変更があり、これらのステップを何度でも行うことができます**：

![](<../../.gitbook/assets/image (574).png>)

### ランダムメモリアドレス - コードの発見

これまで、値を保存しているアドレスを見つける方法を学びましたが、**ゲームの異なる実行ではそのアドレスがメモリの異なる場所にある可能性が高い**です。では、そのアドレスを常に見つける方法を見つけましょう。

前述のトリックのいくつかを使用して、現在のゲームが重要な値を保存しているアドレスを見つけます。次に（ゲームを停止しても構いません）、見つけた**アドレス**を右クリックし、「**このアドレスにアクセスするものを見つける**」または「**このアドレスに書き込むものを見つける**」を選択します：

![](<../../.gitbook/assets/image (1067).png>)

**最初のオプション**は、どの**部分**の**コード**がこの**アドレス**を**使用しているか**を知るのに役立ちます（これは、**ゲームのコードを変更できる場所を知る**など、他の多くのことに役立ちます）。\
**2番目のオプション**はより**具体的**で、**この値がどこから書き込まれているか**を知るのに役立ちます。

これらのオプションのいずれかを選択すると、**デバッガ**がプログラムに**接続**され、新しい**空のウィンドウ**が表示されます。今、**ゲームをプレイ**してその**値を変更**します（ゲームを再起動せずに）。**ウィンドウ**は、**値を変更しているアドレス**で**埋められる**はずです：

![](<../../.gitbook/assets/image (91).png>)

値を変更しているアドレスを見つけたら、**自由にコードを変更**できます（Cheat Engineを使用すると、NOPにすぐに変更できます）：

![](<../../.gitbook/assets/image (1057).png>)

これで、コードがあなたの数値に影響を与えないように変更することができますし、常に良い影響を与えるようにすることもできます。

### ランダムメモリアドレス - ポインタの発見

前のステップに従って、興味のある値がどこにあるかを見つけます。次に、「**このアドレスに書き込むものを見つける**」を使用して、この値を書き込むアドレスを見つけ、それをダブルクリックしてディスアセンブリビューを取得します：

![](<../../.gitbook/assets/image (1039).png>)

次に、**"\[]"の間の16進数値を検索**する新しいスキャンを実行します（この場合、$edxの値）：

![](<../../.gitbook/assets/image (994).png>)

（いくつかが表示される場合は、通常は最小のアドレスのものが必要です）\
これで、**興味のある値を変更するポインタを見つけました**。

「**アドレスを手動で追加**」をクリックします：

![](<../../.gitbook/assets/image (990).png>)

次に、「ポインタ」チェックボックスをクリックし、テキストボックスに見つけたアドレスを追加します（このシナリオでは、前の画像で見つけたアドレスは「Tutorial-i386.exe」+2426B0でした）：

![](<../../.gitbook/assets/image (392).png>)

（最初の「アドレス」は、入力したポインタアドレスから自動的に入力されることに注意してください）

OKをクリックすると、新しいポインタが作成されます：

![](<../../.gitbook/assets/image (308).png>)

これで、その値を変更するたびに、**値があるメモリアドレスが異なっていても重要な値を変更しています**。

### コードインジェクション

コードインジェクションは、ターゲットプロセスにコードの一部を注入し、その後、コードの実行を自分が書いたコードを通過させる技術です（たとえば、ポイントを減らすのではなく与えるなど）。

したがって、プレイヤーのライフから1を引いているアドレスを見つけたと想像してください：

![](<../../.gitbook/assets/image (203).png>)

**ディスアセンブラを表示**して**ディスアセンブルコード**を取得します。\
次に、**CTRL+a**をクリックしてオートアセンブルウィンドウを呼び出し、_**Template --> Code Injection**_ を選択します。

![](<../../.gitbook/assets/image (902).png>)

**変更したい命令のアドレス**を入力します（通常は自動的に入力されます）：

![](<../../.gitbook/assets/image (744).png>)

テンプレートが生成されます：

![](<../../.gitbook/assets/image (944).png>)

したがって、**newmem**セクションに新しいアセンブリコードを挿入し、**originalcode**から元のコードを削除します（実行したくない場合）。この例では、注入されたコードは1を引くのではなく2ポイントを追加します：

![](<../../.gitbook/assets/image (521).png>)

**実行をクリックすると、あなたのコードがプログラムに注入され、機能の動作が変更されるはずです！**

## **参考文献**

* **Cheat Engineチュートリアル、Cheat Engineの使い方を学ぶために完了してください**

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
