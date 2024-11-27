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

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania, gdzie ważne wartości są zapisywane w pamięci działającej gry i ich zmieniania.\
Po pobraniu i uruchomieniu, **zostaniesz** **przedstawiony** z **samouczkiem** jak używać narzędzia. Jeśli chcesz nauczyć się, jak używać narzędzia, zdecydowanie zaleca się jego ukończenie.

## Czego szukasz?

![](<../../.gitbook/assets/image (762).png>)

To narzędzie jest bardzo przydatne do znalezienia **gdzie jakaś wartość** (zwykle liczba) **jest przechowywana w pamięci** programu.\
**Zwykle liczby** są przechowywane w formacie **4 bajtów**, ale możesz je również znaleźć w formatach **double** lub **float**, lub możesz chcieć szukać czegoś **innego niż liczba**. Z tego powodu musisz upewnić się, że **wybierasz** to, co chcesz **wyszukiwać**:

![](<../../.gitbook/assets/image (324).png>)

Możesz również wskazać **różne** typy **wyszukiwań**:

![](<../../.gitbook/assets/image (311).png>)

Możesz także zaznaczyć pole, aby **zatrzymać grę podczas skanowania pamięci**:

![](<../../.gitbook/assets/image (1052).png>)

### Skróty klawiszowe

W _**Edycja --> Ustawienia --> Skróty klawiszowe**_ możesz ustawić różne **skróty klawiszowe** do różnych celów, takich jak **zatrzymanie** **gry** (co jest dość przydatne, jeśli w pewnym momencie chcesz zeskanować pamięć). Inne opcje są dostępne:

![](<../../.gitbook/assets/image (864).png>)

## Modyfikowanie wartości

Gdy **znajdziesz**, gdzie jest **wartość**, której **szukasz** (więcej na ten temat w kolejnych krokach), możesz **zmodyfikować ją**, klikając dwukrotnie, a następnie klikając dwukrotnie jej wartość:

![](<../../.gitbook/assets/image (563).png>)

A na koniec **zaznaczając pole**, aby wprowadzić modyfikację w pamięci:

![](<../../.gitbook/assets/image (385).png>)

**Zmiana** w **pamięci** zostanie natychmiast **zastosowana** (zauważ, że dopóki gra nie użyje tej wartości ponownie, wartość **nie zostanie zaktualizowana w grze**).

## Wyszukiwanie wartości

Załóżmy, że istnieje ważna wartość (jak życie twojego użytkownika), którą chcesz poprawić, i szukasz tej wartości w pamięci.

### Przez znaną zmianę

Zakładając, że szukasz wartości 100, **przeprowadzasz skanowanie** w poszukiwaniu tej wartości i znajdujesz wiele trafień:

![](<../../.gitbook/assets/image (108).png>)

Następnie robisz coś, aby **wartość się zmieniła**, a następnie **zatrzymujesz** grę i **przeprowadzasz** **następne skanowanie**:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine będzie szukać **wartości**, które **zmieniły się z 100 na nową wartość**. Gratulacje, **znalazłeś** **adres** wartości, której szukałeś, teraz możesz ją zmodyfikować.\
Jeśli nadal masz kilka wartości, zrób coś, aby ponownie zmodyfikować tę wartość i przeprowadź kolejne "następne skanowanie", aby przefiltrować adresy.

### Nieznana wartość, znana zmiana

W scenariuszu, w którym **nie znasz wartości**, ale wiesz **jak ją zmienić** (a nawet wartość zmiany), możesz szukać swojej liczby.

Zacznij od przeprowadzenia skanowania typu "**Nieznana początkowa wartość**":

![](<../../.gitbook/assets/image (890).png>)

Następnie zmień wartość, wskaź **jak** **wartość** **się zmieniła** (w moim przypadku zmniejszyła się o 1) i przeprowadź **następne skanowanie**:

![](<../../.gitbook/assets/image (371).png>)

Zostaniesz przedstawiony **wszystkimi wartościami, które zostały zmodyfikowane w wybrany sposób**:

![](<../../.gitbook/assets/image (569).png>)

Gdy znajdziesz swoją wartość, możesz ją zmodyfikować.

Zauważ, że istnieje **wiele możliwych zmian** i możesz powtarzać te **kroki tyle razy, ile chcesz**, aby przefiltrować wyniki:

![](<../../.gitbook/assets/image (574).png>)

### Losowy adres pamięci - Znajdowanie kodu

Do tej pory nauczyliśmy się, jak znaleźć adres przechowujący wartość, ale jest bardzo prawdopodobne, że w **różnych wykonaniach gry ten adres znajduje się w różnych miejscach pamięci**. Więc dowiedzmy się, jak zawsze znaleźć ten adres.

Używając niektórych z wymienionych sztuczek, znajdź adres, w którym twoja aktualna gra przechowuje ważną wartość. Następnie (zatrzymując grę, jeśli chcesz) kliknij prawym przyciskiem myszy na znaleziony **adres** i wybierz "**Dowiedz się, co uzyskuje dostęp do tego adresu**" lub "**Dowiedz się, co zapisuje do tego adresu**":

![](<../../.gitbook/assets/image (1067).png>)

**Pierwsza opcja** jest przydatna, aby wiedzieć, które **części** **kodu** **używają** tego **adresu** (co jest przydatne do innych rzeczy, takich jak **wiedza, gdzie możesz zmodyfikować kod** gry).\
**Druga opcja** jest bardziej **specyficzna** i będzie bardziej pomocna w tym przypadku, ponieważ interesuje nas, **skąd ta wartość jest zapisywana**.

Gdy wybierzesz jedną z tych opcji, **debugger** zostanie **przyłączony** do programu, a nowe **puste okno** się pojawi. Teraz, **graj** w **grę** i **zmodyfikuj** tę **wartość** (bez ponownego uruchamiania gry). **Okno** powinno być **wypełnione** **adresami**, które **zmieniają** **wartość**:

![](<../../.gitbook/assets/image (91).png>)

Teraz, gdy znalazłeś adres, który zmienia wartość, możesz **zmodyfikować kod według własnego uznania** (Cheat Engine pozwala na szybkie modyfikowanie go na NOP):

![](<../../.gitbook/assets/image (1057).png>)

Możesz teraz zmodyfikować go tak, aby kod nie wpływał na twoją liczbę lub zawsze wpływał w pozytywny sposób.

### Losowy adres pamięci - Znajdowanie wskaźnika

Podążając za poprzednimi krokami, znajdź, gdzie znajduje się wartość, która cię interesuje. Następnie, używając "**Dowiedz się, co zapisuje do tego adresu**", dowiedz się, który adres zapisuje tę wartość i kliknij dwukrotnie, aby uzyskać widok disassembly:

![](<../../.gitbook/assets/image (1039).png>)

Następnie przeprowadź nowe skanowanie **szukając wartości hex między "\[]"** (wartość $edx w tym przypadku):

![](<../../.gitbook/assets/image (994).png>)

(_Jeśli pojawi się kilka, zazwyczaj potrzebujesz najmniejszego adresu_)\
Teraz, znaleźliśmy **wskaźnik, który będzie modyfikował wartość, która nas interesuje**.

Kliknij na "**Dodaj adres ręcznie**":

![](<../../.gitbook/assets/image (990).png>)

Teraz zaznacz pole "Wskaźnik" i dodaj znaleziony adres w polu tekstowym (w tym scenariuszu, znaleziony adres na poprzednim obrazie to "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (392).png>)

(Zauważ, że pierwszy "Adres" jest automatycznie wypełniany z adresu wskaźnika, który wprowadzasz)

Kliknij OK, a nowy wskaźnik zostanie utworzony:

![](<../../.gitbook/assets/image (308).png>)

Teraz, za każdym razem, gdy modyfikujesz tę wartość, **modyfikujesz ważną wartość, nawet jeśli adres pamięci, w którym znajduje się wartość, jest inny.**

### Wstrzykiwanie kodu

Wstrzykiwanie kodu to technika, w której wstrzykujesz fragment kodu do docelowego procesu, a następnie przekierowujesz wykonanie kodu, aby przechodziło przez twój własny napisany kod (na przykład przyznając ci punkty zamiast je odejmować).

Wyobraź sobie, że znalazłeś adres, który odejmuje 1 od życia twojego gracza:

![](<../../.gitbook/assets/image (203).png>)

Kliknij na Pokaż disassembler, aby uzyskać **kod disassembly**.\
Następnie kliknij **CTRL+a**, aby wywołać okno Auto assemble i wybierz _**Szablon --> Wstrzykiwanie kodu**_

![](<../../.gitbook/assets/image (902).png>)

Wypełnij **adres instrukcji, którą chcesz zmodyfikować** (zwykle jest to automatycznie wypełnione):

![](<../../.gitbook/assets/image (744).png>)

Zostanie wygenerowany szablon:

![](<../../.gitbook/assets/image (944).png>)

Wstaw swój nowy kod asemblera w sekcji "**newmem**" i usuń oryginalny kod z "**originalcode**", jeśli nie chcesz, aby był wykonywany. W tym przykładzie wstrzyknięty kod doda 2 punkty zamiast odejmować 1:

![](<../../.gitbook/assets/image (521).png>)

**Kliknij na wykonaj i tak dalej, a twój kod powinien zostać wstrzyknięty do programu, zmieniając zachowanie funkcjonalności!**

## **Referencje**

* **Samouczek Cheat Engine, ukończ go, aby nauczyć się, jak zacząć z Cheat Engine**
