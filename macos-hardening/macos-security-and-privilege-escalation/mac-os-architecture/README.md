# macOS Kernel & System Extensions

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

## XNU Kernel

macOSの**コアはXNU**であり、「X is Not Unix」の略です。このカーネルは基本的に**Machマイクロカーネル**（後で説明します）と**Berkeley Software Distribution（BSD）**の要素で構成されています。XNUはまた、**I/O Kitというシステムを介してカーネルドライバのプラットフォームを提供します**。XNUカーネルはDarwinオープンソースプロジェクトの一部であり、**そのソースコードは自由にアクセス可能です**。

セキュリティ研究者やUnix開発者の視点から見ると、**macOS**は**FreeBSD**システムに非常に**似ている**と感じるかもしれません。洗練されたGUIと多数のカスタムアプリケーションを備えています。BSD用に開発されたほとんどのアプリケーションは、macOS上で修正なしにコンパイルして実行できます。Unixユーザーに馴染みのあるコマンドラインツールはすべてmacOSに存在します。しかし、XNUカーネルがMachを組み込んでいるため、従来のUnixライクなシステムとmacOSの間にはいくつかの重要な違いがあり、これらの違いが潜在的な問題を引き起こしたり、独自の利点を提供したりする可能性があります。

XNUのオープンソース版: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Machは**UNIX互換**に設計された**マイクロカーネル**です。その主要な設計原則の1つは、**カーネル**空間で実行される**コード**の量を**最小限に抑え**、ファイルシステム、ネットワーキング、I/Oなどの多くの典型的なカーネル機能を**ユーザーレベルのタスクとして実行できるようにすること**でした。

XNUでは、Machはカーネルが通常処理する多くの重要な低レベル操作、例えばプロセッサスケジューリング、マルチタスク、仮想メモリ管理を**担当しています**。

### BSD

XNUの**カーネル**は、**FreeBSD**プロジェクトから派生したかなりの量のコードも**組み込んでいます**。このコードは**Machとともにカーネルの一部として同じアドレス空間で実行されます**。ただし、XNU内のFreeBSDコードは、Machとの互換性を確保するために修正が必要だったため、元のFreeBSDコードとは大きく異なる場合があります。FreeBSDは以下を含む多くのカーネル操作に寄与しています：

* プロセス管理
* シグナル処理
* ユーザーおよびグループ管理を含む基本的なセキュリティメカニズム
* システムコールインフラ
* TCP/IPスタックとソケット
* ファイアウォールとパケットフィルタリング

BSDとMachの相互作用を理解することは、異なる概念的枠組みのために複雑です。たとえば、BSDはプロセスを基本的な実行単位として使用しますが、Machはスレッドに基づいて動作します。この不一致は、XNU内で**各BSDプロセスを1つのMachスレッドを含むMachタスクに関連付けることによって調整されます**。BSDのfork()システムコールが使用されると、カーネル内のBSDコードはMach関数を使用してタスクとスレッド構造を作成します。

さらに、**MachとBSDはそれぞれ異なるセキュリティモデルを維持しています**：**Machの**セキュリティモデルは**ポート権**に基づいていますが、BSDのセキュリティモデルは**プロセス所有権**に基づいています。これら2つのモデルの間の不一致は、時折ローカル特権昇格の脆弱性を引き起こすことがあります。一般的なシステムコールに加えて、**ユーザースペースプログラムがカーネルと相互作用することを可能にするMachトラップもあります**。これらの異なる要素が組み合わさって、macOSカーネルの多面的でハイブリッドなアーキテクチャを形成しています。

### I/O Kit - ドライバ

I/O Kitは、XNUカーネル内のオープンソースのオブジェクト指向**デバイスドライバフレームワーク**であり、**動的にロードされるデバイスドライバ**を処理します。これにより、さまざまなハードウェアをサポートするために、カーネルにモジュラーコードをその場で追加できます。

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - プロセス間通信

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

## macOSカーネル拡張

macOSは**カーネル拡張**（.kext）をロードすることに対して**非常に制限が厳しい**です。実際、デフォルトではバイパスが見つからない限り、ほぼ不可能です。

次のページでは、macOSが**kernelcache**内にロードする`.kext`を回復する方法も見ることができます：

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOSシステム拡張

カーネル拡張の代わりに、macOSはシステム拡張を作成しました。これにより、カーネルと相互作用するためのユーザーレベルのAPIが提供されます。この方法により、開発者はカーネル拡張を使用せずに済みます。

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## 参考文献

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

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
