# Runbook sprzętowego demo ESP32

## Zestaw

- 1 × Red ESP — `esp-attacker/`;
- 3 × identyczny receiver/bridge — `esp-sniffer-demo/`;
- 1 × ESP32 z OLED SSD1306 128×64 — `esp-oled-monitor/`;
- laptop z backendem i dashboardem;
- telefon udostępniający hotspot 2,4 GHz.

Żaden ESP nie potrzebuje stałego adresu IP. Każdy sniffer tworzy `node_id` z
własnego eFuse MAC, więc ten sam firmware można wgrać na wszystkie trzy płytki.
W konfiguracji snifferów podaje się jedynie aktualny adres laptopa z backendem.

## 1. Hotspot i laptop

1. Nazwij hotspot np. `LAB_TUM_DEMO` — prefiks `LAB_` jest blokadą Red ESP.
2. Włącz pasmo 2,4 GHz. Na iPhone włącz „Maksymalizuj zgodność”.
3. Połącz laptop z hotspotem i sprawdź jego adres poleceniem `ipconfig`.
4. Uruchom backend na wszystkich interfejsach:

   ```powershell
   cd backend
   $env:MOCK="0"
   uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

5. W drugim terminalu uruchom dashboard:

   ```powershell
   cd dashboard
   npm run dev -- --host 0.0.0.0
   ```

Zapora Windows musi pozwalać na prywatny ruch przychodzący TCP/8000. Niektóre
hotspoty izolują klientów; przed demo sprawdź z drugiego urządzenia
`http://ADRES_LAPTOPA:8000/health`. Jeżeli nie odpowiada, użyj hotspotu laptopa
lub małego routera. ESP-NOW i OLED nadal działają niezależnie od tej izolacji,
ale sniffery potrzebują HTTP do backendu.

## 2. Red ESP

```powershell
cd esp-attacker
Copy-Item include\lab_secrets.example.h include\lab_secrets.h
notepad include\lab_secrets.h
uvx --from platformio platformio run -e esp32dev --target upload
```

Ustaw w sekretach nazwę i hasło hotspotu oraz osobne hasło panelu. Nie wpisuje
się żadnych adresów ESP.

## 3. Trzy sniffery

```powershell
cd esp-sniffer-demo
Copy-Item include\lab_secrets.example.h include\lab_secrets.h
notepad include\lab_secrets.h
```

Ustaw wspólny hotspot i adres laptopa, np.:

```cpp
#define LAB_WIFI_SSID "LAB_TUM_DEMO"
#define LAB_WIFI_PASSWORD "haslo-hotspotu"
#define BACKEND_BASE_URL "http://192.168.43.100:8000"
```

Podłączaj kolejno każdą z trzech płytek i wykonuj:

```powershell
uvx --from platformio platformio run -e esp32dev --target upload
```

Receiver synchronizuje czas przez NTP, odbiera wyłącznie pakiety `TUMD` z
poprawną checksumą, agreguje je przez sekundę i wysyła jeden zgodny z zamrożonym
kontraktem POST `/ingest`. Dla deauth ustawia `frame_type=mgmt`, `subtype=12` i
`guessed_type=synthetic_deauth_flood`.

## 4. ESP z OLED

Domyślne ustawienia zakładają SSD1306 I2C `0x3C`, SDA=GPIO21, SCL=GPIO22.

```powershell
cd esp-oled-monitor
Copy-Item include\lab_secrets.example.h include\lab_secrets.h
notepad include\lab_secrets.h
uvx --from platformio platformio run -e esp32dev --target upload
```

OLED odbiera ten sam broadcast bez backendu. Przez pięć sekund pokazuje typ i
logiczne tempo scenariusza, a później wraca do `BRAK ATAKU`.

## 5. Przebieg prezentacji

1. Włącz hotspot, backend i dashboard.
2. Zasil trzy sniffery, OLED oraz Red ESP.
3. Poczekaj, aż dashboard pokaże trzy aktywne nody.
4. Na laptopie otwórz `http://red-esp.local` i zaloguj się jako `redesp`.
5. Wybierz `Deauthentication flood (SIMULATED)`, 10 pakietów/s i 5 sekund.
6. Przytrzymaj BOOT na Red ESP przez 1,5 s i kliknij START.
7. OLED natychmiast pokaże alarm; sniffery w ciągu około sekundy zgłoszą
   syntetyczne ramki, a dashboard pokaże agent → oracle → deploy.

Jeśli mDNS na hotspocie nie działa, adres Red ESP jest drukowany na serialu.
Awaryjny panel `RED-ESP-*` wymaga drugiego telefonu — laptop z backendem powinien
pozostać połączony z głównym hotspotem.
