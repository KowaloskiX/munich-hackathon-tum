# Defense HMI — Waveshare ESP32-S3-Touch-LCD-1.28

Firmware terminala alarmowego dla płytki Waveshare
`ESP32-S3-Touch-LCD-1.28` (SKU 25098/26959). Domyślny profil używa dokładnego
pinoutu płytki: okrągły LCD GC9A01A 240×240 oraz dotyk CST816S.

## Co pokazuje ekran

- `BEZPIECZNIE` — zielony ekran jest możliwy wyłącznie po świeżym statusie
  `SAFE` oraz gdy wszystkie oczekiwane sensory są online.
- `ATAK` — czerwony, pulsujący alarm z typem ataku, węzłem i czasem trwania.
  Alarm jest zatrzaśnięty do czasu jawnego, poprawnego `SAFE` z backendu.
- `BRAK DANYCH` — status bez aktywnego alarmu wygasł albo backend jest
  niedostępny; urządzenie nigdy nie zamienia tego stanu na zielony. Już znany
  atak pozostaje czerwony i dostaje etykietę o wygaśnięciu danych.
- `KONFIGURACJA` / `ŁĄCZENIE` — brak lokalnej konfiguracji albo trwa łączenie.

Dotknięcie ekranu przełącza widok szczegółów. Dotyk nie kasuje i nie potwierdza
alarmu, więc przypadkowe naciśnięcie nie ukryje incydentu.

## Sprzęt

| Funkcja | Układ / pin |
|---|---|
| LCD | GC9A01A, SPI, 240×240 |
| LCD MISO / MOSI / SCLK | GPIO12 / GPIO11 / GPIO10 |
| LCD CS / DC / RST / BL | GPIO9 / GPIO8 / GPIO14 / GPIO2 |
| LCD SPI clock | 40 MHz (official TFT_eSPI Setup302 profile) |
| Dotyk | CST816S, I²C address `0x15` |
| Touch SDA / SCL / RST / IRQ | GPIO6 / GPIO7 / GPIO13 / GPIO5 |
| Flash / PSRAM | 16 MB / 2 MB Quad SPI (QSPI) |

Pinout i kontrolery są zgodne z
[dokumentacją Waveshare](https://docs.waveshare.com/ESP32-S3-Touch-LCD-1.28).

## Najszybszy test ekranu

Tryb demo nie wymaga Wi-Fi ani backendu. Przełącza `BEZPIECZNIE` i `ATAK` co
8 sekund:

```bash
pio run -d firmware/esp32-display \
  -e waveshare-s3-touch-lcd-1_28-demo -t upload
pio device monitor -b 115200
```

Nie używaj profilu `-demo` jako rzeczywistego terminala bezpieczeństwa.

## Konfiguracja rzeczywistego backendu

Repo nie zawiera jeszcze produkcyjnej implementacji backendu. Adres podany w
konfiguracji musi udostępniać opisany niżej endpoint HTTP oraz event WebSocket;
do testu stanowiskowego służy dołączony mock HTTP.

Skopiuj plik konfiguracyjny i wpisz SSID, hasło oraz adres backendu:

```bash
cp firmware/esp32-display/include/secrets.example.h \
  firmware/esp32-display/include/secrets.h
```

`include/secrets.h` jest ignorowany przez Git. Następnie:

```bash
pio run -d firmware/esp32-display
pio run -d firmware/esp32-display -t upload
pio device monitor -b 115200
```

Domyślne środowisko to `waveshare-s3-touch-lcd-1_28`. Jeśli automatyczne
wykrycie portu nie zadziała, sprawdź `pio device list` i dodaj `upload_port` w
lokalnej konfiguracji PlatformIO.

### Test z mockiem HTTP

Do repo jest dołączony backend testowy bez dodatkowych zależności:

```bash
python3 firmware/esp32-display/tools/mock_hmi_backend.py
```

W `secrets.h` ustaw `HMI_BACKEND_HOST` na adres IP komputera w tej samej sieci.
Stan można przełączać z drugiego terminala:

```bash
curl -X POST http://localhost:8000/demo/attack
curl -X POST http://localhost:8000/demo/safe
curl -X POST http://localhost:8000/demo/unknown
```

Mock obsługuje polling HTTP, ale nie WebSocket; ekran aktualizuje się najpóźniej
po około 3 sekundach. Domyślne `HMI_ENABLE_WEBSOCKET=0` zapobiega blokującym
próbom połączenia z nieistniejącym kanałem live. Ustaw wartość `1` dopiero dla
backendu implementującego poniższy kontrakt WebSocket.

## Kontrakt HTTP

Urządzenie pobiera co 3 sekundy:

```http
GET /v1/hmi/status?node_id=hmi-01
Accept: application/json
Authorization: Bearer <token>   # jeśli skonfigurowano
```

Odpowiedź `SAFE`:

```json
{
  "schema_version": 1,
  "stream_generation": 17,
  "stream_id": "backend-boot-c8d1",
  "seq": 42,
  "status": "SAFE",
  "valid_for_ms": 10000,
  "active_alerts": 0,
  "incident": null,
  "sensors": {"online": 3, "expected": 3},
  "metrics": {"attack_frames_detected": 247}
}
```

Odpowiedź `ATTACK`:

```json
{
  "schema_version": 1,
  "stream_generation": 17,
  "stream_id": "backend-boot-c8d1",
  "seq": 43,
  "status": "ATTACK",
  "valid_for_ms": 10000,
  "active_alerts": 1,
  "incident": {
    "id": "inc-7",
    "node_id": "esp-03",
    "attack_class": "deauth_flood"
  },
  "sensors": {"online": 3, "expected": 3},
  "metrics": {"attack_frames_detected": 247}
}
```

Wymagane są: `schema_version`, dodatnie `stream_generation`, niepusty
`stream_id`, `seq`, `status`, `valid_for_ms`, `active_alerts` oraz liczbowe
`sensors.online` i `sensors.expected`. `status` przyjmuje `SAFE`, `ATTACK` lub
`UNKNOWN`; `SAFE` dodatkowo wymaga `sensors.expected > 0` i pełnej dostępności
sensorów. `valid_for_ms < 500` jest odrzucane, a wartości powyżej 30000 ms są
ograniczane do 30000 ms; TTL mierzy lokalny zegar monotoniczny ESP. Odpowiedź
HTTP musi mieć `Content-Length` i nie może przekroczyć 4096 bajtów.

Backend przechowuje `stream_generation` trwale i zwiększa je przed każdym
nowym procesem/strumieniem; `stream_id` jest unikalne dla tego strumienia, a
`seq` rośnie przy każdej zmianie agregatu bezpieczeństwa. Firmware odrzuca
starszą generację, cofnięty numer, inny identyfikator w tej samej generacji i
sprzeczną treść z tym samym `seq`. Identyczny snapshot HTTP z tym samym `seq`
może jedynie odświeżyć TTL.

## WebSocket

Po ustawieniu `HMI_ENABLE_WEBSOCKET=1` firmware łączy się również z
`/v1/hmi/live?node_id=hmi-01`. Autorytatywna wiadomość ma typ `SYSTEM_STATUS`, a
`payload` jest dokładnie takim samym snapshotem jak odpowiedź HTTP. Pola
kolejności w zewnętrznej kopercie muszą dokładnie zgadzać się z polami w
`payload`:

```json
{
  "schema_version": 1,
  "event_id": "ws-99",
  "stream_generation": 17,
  "stream_id": "backend-boot-c8d1",
  "seq": 43,
  "type": "SYSTEM_STATUS",
  "node_id": "hmi-01",
  "ts": 1786999900.5,
  "payload": {
    "schema_version": 1,
    "stream_generation": 17,
    "stream_id": "backend-boot-c8d1",
    "seq": 43,
    "status": "ATTACK",
    "valid_for_ms": 10000,
    "active_alerts": 1,
    "incident": {
      "id": "inc-7",
      "node_id": "esp-03",
      "attack_class": "deauth_flood"
    },
    "sensors": {"online": 3, "expected": 3},
    "metrics": {"attack_frames_detected": 247}
  }
}
```

Eventy etapów pipeline, takie jak `ANOMALY_DETECTED` czy `DEPLOYED`, są przez
HMI ignorowane. Nie zawierają kompletnego stanu agregatu i nie mogą ani włączyć,
ani wyczyścić alarmu. Każda zmiana zagrożenia musi wygenerować pełny,
uporządkowany `SYSTEM_STATUS`.

### Multicast dla sieci z izolacją klientów

Jeżeli WLAN blokuje bezpośrednie TCP między klientami, ustaw
`HMI_ENABLE_MULTICAST=1`. Backend uruchomiony z `HARDWARE_MULTICAST=1`
publikuje ten sam pełny `SYSTEM_STATUS` na `239.255.77.78:37778`. Równe,
identyczne sekwencje są akceptowane wyłącznie jako odświeżenie TTL; starsze lub
sprzeczne statusy nadal są odrzucane.

## Walidacja

```bash
pio test -d firmware/esp32-display -e native
pio run -d firmware/esp32-display -e waveshare-s3-touch-lcd-1_28
pio run -d firmware/esp32-display -e waveshare-s3-touch-lcd-1_28-demo
```

Testy hostowe sprawdzają m.in. wygaśnięcie `SAFE`, niepełną flotę,
zatrzaśnięcie alarmu, przepełnienie `millis()` oraz odrzucanie starych i
sprzecznych sekwencji. Parser JSON jest dodatkowo ograniczony schematem,
rozmiarem 4096 bajtów i maksymalnym poziomem zagnieżdżenia 8.

## Granica bezpieczeństwa

Konfiguracja sieciowa używa HTTP/WS i jest przeznaczona do izolowanego demo.
Poza taką siecią należy przejść na HTTPS/WSS, zweryfikować certyfikat serwera i
używać unikalnego tokenu lub certyfikatu urządzenia. Ekran jest terminalem HMI;
nie sniffuje ani nie blokuje ramek radiowych.
