# Benutzer-Namespace

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Grundinformationen

Ein Benutzer-Namespace ist eine Funktion des Linux-Kernels, die **die Isolation von Benutzer- und Gruppen-ID-Zuordnungen bereitstellt**, sodass jeder Benutzer-Namespace **sein eigenes Set von Benutzer- und Gruppen-IDs** haben kann. Diese Isolation ermöglicht es Prozessen, die in verschiedenen Benutzer-Namespaces ausgeführt werden, **unterschiedliche Berechtigungen und Eigentum zu haben**, selbst wenn sie numerisch dieselben Benutzer- und Gruppen-IDs teilen.

Benutzer-Namespaces sind besonders nützlich in der Containerisierung, wo jeder Container sein eigenes unabhängiges Set von Benutzer- und Gruppen-IDs haben sollte, was eine bessere Sicherheit und Isolation zwischen Containern und dem Host-System ermöglicht.

### So funktioniert es:

1. Wenn ein neuer Benutzer-Namespace erstellt wird, **beginnt er mit einem leeren Set von Benutzer- und Gruppen-ID-Zuordnungen**. Das bedeutet, dass jeder Prozess, der im neuen Benutzer-Namespace ausgeführt wird, **anfänglich keine Berechtigungen außerhalb des Namespaces hat**.
2. ID-Zuordnungen können zwischen den Benutzer- und Gruppen-IDs im neuen Namespace und denen im übergeordneten (oder Host-) Namespace hergestellt werden. Dies **ermöglicht es Prozessen im neuen Namespace, Berechtigungen und Eigentum zu haben, die den Benutzer- und Gruppen-IDs im übergeordneten Namespace entsprechen**. Die ID-Zuordnungen können jedoch auf bestimmte Bereiche und Teilmengen von IDs beschränkt werden, was eine feinkörnige Kontrolle über die Berechtigungen ermöglicht, die Prozessen im neuen Namespace gewährt werden.
3. Innerhalb eines Benutzer-Namespace können **Prozesse volle Root-Berechtigungen (UID 0) für Operationen innerhalb des Namespaces haben**, während sie außerhalb des Namespaces weiterhin eingeschränkte Berechtigungen haben. Dies ermöglicht es, **Container mit root-ähnlichen Fähigkeiten innerhalb ihres eigenen Namespaces auszuführen, ohne volle Root-Berechtigungen auf dem Host-System zu haben**.
4. Prozesse können zwischen Namespaces mit dem `setns()` Systemaufruf wechseln oder neue Namespaces mit den Systemaufrufen `unshare()` oder `clone()` mit dem `CLONE_NEWUSER`-Flag erstellen. Wenn ein Prozess zu einem neuen Namespace wechselt oder einen erstellt, beginnt er, die Benutzer- und Gruppen-ID-Zuordnungen zu verwenden, die mit diesem Namespace verbunden sind.

## Labor:

### Erstellen Sie verschiedene Namespaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Durch das Einhängen einer neuen Instanz des `/proc`-Dateisystems, wenn Sie den Parameter `--mount-proc` verwenden, stellen Sie sicher, dass der neue Mount-Namespace eine **genaue und isolierte Sicht auf die prozessspezifischen Informationen hat, die für diesen Namespace spezifisch sind**.

<details>

<summary>Fehler: bash: fork: Kann Speicher nicht zuweisen</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler auf, der auf die Art und Weise zurückzuführen ist, wie Linux neue PID (Prozess-ID) Namespaces behandelt. Die wichtigsten Details und die Lösung sind unten aufgeführt:

1. **Problemerklärung**:
- Der Linux-Kernel erlaubt es einem Prozess, neue Namespaces mit dem Systemaufruf `unshare` zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespace initiiert (als "unshare"-Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
- Das Ausführen von `%unshare -p /bin/bash%` startet `/bin/bash` im selben Prozess wie `unshare`. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird zu PID 1. Wenn dieser Prozess beendet wird, wird die Bereinigung des Namespaces ausgelöst, wenn keine anderen Prozesse vorhanden sind, da PID 1 die besondere Rolle hat, verwaiste Prozesse zu übernehmen. Der Linux-Kernel deaktiviert dann die PID-Zuweisung in diesem Namespace.

2. **Folge**:
- Das Beenden von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING`-Flags. Dies führt dazu, dass die Funktion `alloc_pid` fehlschlägt, wenn versucht wird, eine neue PID zuzuweisen, was den Fehler "Kann Speicher nicht zuweisen" erzeugt.

3. **Lösung**:
- Das Problem kann gelöst werden, indem die Option `-f` mit `unshare` verwendet wird. Diese Option bewirkt, dass `unshare` einen neuen Prozess nach der Erstellung des neuen PID-Namespace forked.
- Das Ausführen von `%unshare -fp /bin/bash%` stellt sicher, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, wodurch das vorzeitige Beenden von PID 1 verhindert wird und eine normale PID-Zuweisung ermöglicht wird.

Durch die Sicherstellung, dass `unshare` mit dem `-f`-Flag ausgeführt wird, wird der neue PID-Namespace korrekt aufrechterhalten, sodass `/bin/bash` und seine Unterprozesse ohne den Speicherzuweisungsfehler arbeiten können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Um den Benutzernamespace zu verwenden, muss der Docker-Daemon mit **`--userns-remap=default`** gestartet werden (In Ubuntu 14.04 kann dies durch Ändern von `/etc/default/docker` und anschließendes Ausführen von `sudo service docker restart` erfolgen)

### &#x20;Überprüfen, in welchem Namespace sich Ihr Prozess befindet
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Es ist möglich, die Benutzerzuordnung aus dem Docker-Container mit folgendem Befehl zu überprüfen:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Oder vom Host mit:
```bash
cat /proc/<pid>/uid_map
```
### Finde alle Benutzer-Namensräume

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Betreten Sie einen Benutzer-Namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Außerdem können Sie **nur in einen anderen Prozess-Namespace eintreten, wenn Sie root sind**. Und Sie **können** **nicht** **in** einen anderen Namespace **eintreten**, **ohne** einen Deskriptor, der darauf verweist (wie `/proc/self/ns/user`).

### Erstellen Sie einen neuen Benutzer-Namespace (mit Zuordnungen)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Wiederherstellung von Fähigkeiten

Im Fall von Benutzer-Namensräumen gilt: **Wenn ein neuer Benutzer-Namensraum erstellt wird, erhält der Prozess, der in den Namensraum eintritt, ein vollständiges Set von Fähigkeiten innerhalb dieses Namensraums**. Diese Fähigkeiten ermöglichen es dem Prozess, privilegierte Operationen wie **das Einhängen von** **Dateisystemen**, das Erstellen von Geräten oder das Ändern des Eigentums von Dateien durchzuführen, jedoch **nur im Kontext seines Benutzer-Namensraums**.

Zum Beispiel, wenn Sie die Fähigkeit `CAP_SYS_ADMIN` innerhalb eines Benutzer-Namensraums haben, können Sie Operationen durchführen, die typischerweise diese Fähigkeit erfordern, wie das Einhängen von Dateisystemen, jedoch nur im Kontext Ihres Benutzer-Namensraums. Alle Operationen, die Sie mit dieser Fähigkeit durchführen, haben keine Auswirkungen auf das Host-System oder andere Namensräume.

{% hint style="warning" %}
Daher, selbst wenn das Erhalten eines neuen Prozesses in einem neuen Benutzer-Namensraum **Ihnen alle Fähigkeiten zurückgibt** (CapEff: 000001ffffffffff), können Sie tatsächlich **nur die verwenden, die mit dem Namensraum verbunden sind** (zum Beispiel mount), aber nicht jede. Daher ist dies für sich genommen nicht ausreichend, um aus einem Docker-Container zu entkommen.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
