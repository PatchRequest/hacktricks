# Cheat Engine

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind und sie zu ändern.\
Wenn du es herunterlädst und ausführst, wirst du mit einem **Tutorial** konfrontiert, wie man das Tool benutzt. Wenn du lernen möchtest, wie man das Tool verwendet, wird dringend empfohlen, es abzuschließen.

## Was suchst du?

![](<../../.gitbook/assets/image (762).png>)

Dieses Tool ist sehr nützlich, um **herauszufinden, wo ein Wert** (normalerweise eine Zahl) **im Speicher** eines Programms **gespeichert ist**.\
**Normalerweise werden Zahlen** in **4 Bytes** Form gespeichert, aber du könntest sie auch in **double** oder **float** Formaten finden, oder du möchtest nach etwas **anderem als einer Zahl** suchen. Aus diesem Grund musst du sicherstellen, dass du **auswählst**, wonach du **suchen möchtest**:

![](<../../.gitbook/assets/image (324).png>)

Außerdem kannst du **verschiedene** Arten von **Suchen** angeben:

![](<../../.gitbook/assets/image (311).png>)

Du kannst auch das Kästchen ankreuzen, um **das Spiel während des Scannens des Speichers zu stoppen**:

![](<../../.gitbook/assets/image (1052).png>)

### Hotkeys

In _**Bearbeiten --> Einstellungen --> Hotkeys**_ kannst du verschiedene **Hotkeys** für verschiedene Zwecke festlegen, wie z.B. **das Spiel zu stoppen** (was sehr nützlich ist, wenn du zu einem bestimmten Zeitpunkt den Speicher scannen möchtest). Weitere Optionen sind verfügbar:

![](<../../.gitbook/assets/image (864).png>)

## Wert ändern

Sobald du **gefunden** hast, wo der **Wert** ist, den du **suchst** (mehr dazu in den folgenden Schritten), kannst du ihn **ändern**, indem du doppelt darauf klickst und dann erneut auf seinen Wert doppelt klickst:

![](<../../.gitbook/assets/image (563).png>)

Und schließlich **das Kästchen ankreuzen**, um die Änderung im Speicher vorzunehmen:

![](<../../.gitbook/assets/image (385).png>)

Die **Änderung** im **Speicher** wird sofort **angewendet** (beachte, dass der Wert **nicht im Spiel aktualisiert wird**, bis das Spiel diesen Wert nicht erneut verwendet).

## Wert suchen

Angenommen, es gibt einen wichtigen Wert (wie das Leben deines Benutzers), den du verbessern möchtest, und du suchst nach diesem Wert im Speicher.

### Durch eine bekannte Änderung

Angenommen, du suchst nach dem Wert 100, du **führst einen Scan** durch, um nach diesem Wert zu suchen, und findest viele Übereinstimmungen:

![](<../../.gitbook/assets/image (108).png>)

Dann machst du etwas, damit sich der **Wert ändert**, und du **stopst** das Spiel und **führst** einen **nächsten Scan** durch:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine wird nach den **Werten** suchen, die **von 100 auf den neuen Wert** gewechselt sind. Glückwunsch, du **hast** die **Adresse** des Wertes gefunden, den du gesucht hast, und kannst ihn jetzt ändern.\
Wenn du immer noch mehrere Werte hast, mache etwas, um diesen Wert erneut zu ändern, und führe einen weiteren "nächsten Scan" durch, um die Adressen zu filtern.

### Unbekannter Wert, bekannte Änderung

In dem Szenario, dass du **den Wert nicht kennst**, aber weißt, **wie man ihn ändert** (und sogar den Wert der Änderung), kannst du nach deiner Zahl suchen.

Beginne also mit einem Scan vom Typ "**Unbekannter Anfangswert**":

![](<../../.gitbook/assets/image (890).png>)

Dann ändere den Wert, gib an, **wie** sich der **Wert** **geändert hat** (in meinem Fall wurde er um 1 verringert) und führe einen **nächsten Scan** durch:

![](<../../.gitbook/assets/image (371).png>)

Dir werden **alle Werte angezeigt, die auf die ausgewählte Weise geändert wurden**:

![](<../../.gitbook/assets/image (569).png>)

Sobald du deinen Wert gefunden hast, kannst du ihn ändern.

Beachte, dass es **viele mögliche Änderungen** gibt und du diese **Schritte so oft du willst** wiederholen kannst, um die Ergebnisse zu filtern:

![](<../../.gitbook/assets/image (574).png>)

### Zufällige Speicheradresse - Den Code finden

Bis jetzt haben wir gelernt, wie man eine Adresse findet, die einen Wert speichert, aber es ist sehr wahrscheinlich, dass in **verschiedenen Ausführungen des Spiels diese Adresse an verschiedenen Stellen im Speicher** ist. Lass uns also herausfinden, wie man diese Adresse immer findet.

Verwende einige der erwähnten Tricks, um die Adresse zu finden, an der dein aktuelles Spiel den wichtigen Wert speichert. Dann (stoppe das Spiel, wenn du möchtest) mache einen **Rechtsklick** auf die gefundene **Adresse** und wähle "**Herausfinden, was auf diese Adresse zugreift**" oder "**Herausfinden, was in diese Adresse schreibt**":

![](<../../.gitbook/assets/image (1067).png>)

Die **erste Option** ist nützlich, um zu wissen, welche **Teile** des **Codes** diese **Adresse** **verwenden** (was für mehr Dinge nützlich ist, wie z.B. **zu wissen, wo du den Code** des Spiels **ändern kannst**).\
Die **zweite Option** ist spezifischer und wird in diesem Fall hilfreicher sein, da wir daran interessiert sind zu wissen, **von wo dieser Wert geschrieben wird**.

Sobald du eine dieser Optionen ausgewählt hast, wird der **Debugger** an das Programm **angehängt** und ein neues **leeres Fenster** erscheint. Jetzt **spiele** das **Spiel** und **ändere** diesen **Wert** (ohne das Spiel neu zu starten). Das **Fenster** sollte mit den **Adressen** gefüllt sein, die den **Wert** **ändern**:

![](<../../.gitbook/assets/image (91).png>)

Jetzt, da du die Adresse gefunden hast, die den Wert ändert, kannst du **den Code nach Belieben ändern** (Cheat Engine ermöglicht es dir, ihn schnell in NOPs zu ändern):

![](<../../.gitbook/assets/image (1057).png>)

So kannst du ihn jetzt so ändern, dass der Code deine Zahl nicht beeinflusst oder immer positiv beeinflusst.

### Zufällige Speicheradresse - Den Zeiger finden

Folge den vorherigen Schritten, um herauszufinden, wo sich der Wert befindet, der dich interessiert. Verwende dann "**Herausfinden, was in diese Adresse schreibt**", um herauszufinden, welche Adresse diesen Wert schreibt, und doppelklicke darauf, um die Disassemblierungsansicht zu erhalten:

![](<../../.gitbook/assets/image (1039).png>)

Führe dann einen neuen Scan durch, **indem du nach dem hexadezimalen Wert zwischen "\[]" suchst** (den Wert von $edx in diesem Fall):

![](<../../.gitbook/assets/image (994).png>)

(_Wenn mehrere erscheinen, benötigst du normalerweise die kleinste Adresse_)\
Jetzt haben wir den **Zeiger gefunden, der den Wert ändert, der uns interessiert**.

Klicke auf "**Adresse manuell hinzufügen**":

![](<../../.gitbook/assets/image (990).png>)

Klicke jetzt auf das Kontrollkästchen "Zeiger" und füge die gefundene Adresse in das Textfeld ein (in diesem Szenario war die gefundene Adresse im vorherigen Bild "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (392).png>)

(Beachte, wie die erste "Adresse" automatisch mit der Zeigeradresse ausgefüllt wird, die du eingibst)

Klicke auf OK und ein neuer Zeiger wird erstellt:

![](<../../.gitbook/assets/image (308).png>)

Jetzt, jedes Mal, wenn du diesen Wert änderst, änderst du **den wichtigen Wert, auch wenn die Speicheradresse, an der der Wert gespeichert ist, unterschiedlich ist.**

### Code-Injektion

Code-Injektion ist eine Technik, bei der du ein Stück Code in den Zielprozess injizierst und dann die Ausführung des Codes so umleitest, dass sie durch deinen eigenen geschriebenen Code geht (zum Beispiel, um dir Punkte zu geben, anstatt sie abzuziehen).

Stell dir vor, du hast die Adresse gefunden, die 1 vom Leben deines Spielers abzieht:

![](<../../.gitbook/assets/image (203).png>)

Klicke auf "Disassembler anzeigen", um den **disassemblierten Code** zu erhalten.\
Klicke dann auf **CTRL+a**, um das Auto-Assembly-Fenster aufzurufen, und wähle _**Vorlage --> Code-Injektion**_

![](<../../.gitbook/assets/image (902).png>)

Fülle die **Adresse der Anweisung aus, die du ändern möchtest** (dies wird normalerweise automatisch ausgefüllt):

![](<../../.gitbook/assets/image (744).png>)

Eine Vorlage wird generiert:

![](<../../.gitbook/assets/image (944).png>)

Füge deinen neuen Assembly-Code in den Abschnitt "**newmem**" ein und entferne den ursprünglichen Code aus dem "**originalcode**", wenn du nicht möchtest, dass er ausgeführt wird. In diesem Beispiel wird der injizierte Code 2 Punkte hinzufügen, anstatt 1 abzuziehen:

![](<../../.gitbook/assets/image (521).png>)

**Klicke auf Ausführen und so weiter, und dein Code sollte in das Programm injiziert werden, wodurch das Verhalten der Funktionalität geändert wird!**

## **Referenzen**

* **Cheat Engine Tutorial, schließe es ab, um zu lernen, wie man mit Cheat Engine anfängt**
