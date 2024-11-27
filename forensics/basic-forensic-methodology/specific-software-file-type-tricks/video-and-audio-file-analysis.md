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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**モバイルセキュリティ**の専門知識を8kSecアカデミーで深めましょう。自己ペースのコースを通じてiOSとAndroidのセキュリティをマスターし、認定を取得しましょう：

{% embed url="https://academy.8ksec.io/" %}

**音声および動画ファイルの操作**は、**CTFフォレンジックチャレンジ**の定番であり、**ステガノグラフィー**やメタデータ分析を利用して秘密のメッセージを隠したり明らかにしたりします。**[mediainfo](https://mediaarea.net/en/MediaInfo)**や**`exiftool`**などのツールは、ファイルのメタデータを検査し、コンテンツタイプを特定するために不可欠です。

音声チャレンジでは、**[Audacity](http://www.audacityteam.org/)**が波形を表示し、音声に埋め込まれたテキストを明らかにするために必要なスペクトログラムを分析するための主要なツールとして際立っています。詳細なスペクトログラム分析には**[Sonic Visualiser](http://www.sonicvisualiser.org/)**が強く推奨されます。**Audacity**は、隠されたメッセージを検出するためにトラックを遅くしたり逆再生したりする音声操作を可能にします。**[Sox](http://sox.sourceforge.net/)**は、音声ファイルの変換と編集に優れたコマンドラインユーティリティです。

**最下位ビット（LSB）**操作は、音声および動画のステガノグラフィーで一般的な手法であり、メディアファイルの固定サイズのチャンクを利用してデータを目立たないように埋め込むことができます。**[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**は、**DTMFトーン**や**モールス信号**として隠されたメッセージをデコードするのに役立ちます。

動画チャレンジは、音声と動画のストリームをバンドルするコンテナ形式を含むことがよくあります。**[FFmpeg](http://ffmpeg.org/)**は、これらの形式を分析し操作するための定番であり、デマルチプレックスやコンテンツの再生が可能です。開発者向けには、**[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**がFFmpegの機能をPythonに統合し、高度なスクリプト可能なインタラクションを提供します。

これらのツールの配列は、CTFチャレンジで必要とされる多様性を強調しており、参加者は音声および動画ファイル内の隠されたデータを明らかにするために幅広い分析および操作技術を駆使しなければなりません。

## 参考文献
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**モバイルセキュリティ**の専門知識を8kSecアカデミーで深めましょう。自己ペースのコースを通じてiOSとAndroidのセキュリティをマスターし、認定を取得しましょう：

{% embed url="https://academy.8ksec.io/" %}

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
