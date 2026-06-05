# START HERE — запуск SCA-комплекса с нуля (для коллеги)

Комплекс анализирует артефакты на уязвимости: перетащил файл в веб-интерфейс →
получил отчёт (Syft + Grype + Trivy). **Всё приходит через `git clone`** — код,
docker-образы и базы уязвимостей. На машине ничего не качается и не собирается.

---

## Что нужно заранее (один раз)

- **Docker** + docker compose v2 (Docker Desktop на Windows / `docker` на Linux), **запущен**.
- **git** и **git-lfs** (образы/базы лежат в репозитории через Git LFS).
- **Python 3.10+**.

Проверка:
```bash
docker version            # должна быть секция Server
git lfs version
python3 --version         # (на Windows: python --version)
```

---

## 1. Склонировать (с LFS — тянет образы и базы, ~3 ГБ)

**Linux / Ubuntu:**
```bash
sudo apt-get install -y git-lfs && git lfs install
git clone https://gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble.git
cd el-sca-ansamble
```

**Windows (PowerShell):**
```powershell
git lfs install
git clone https://gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble.git
cd el-sca-ansamble
```

Проверь, что бандл реально скачался (а не LFS-указатели):
```bash
ls -lh bundle/      # файлы должны весить ГБ (а не ~130 байт)
```
Если там крошечные файлы — git-lfs не сработал: `git lfs pull`.

---

## 2. Развернуть (загрузит образы, восстановит базы, включит офлайн)

**Linux:**
```bash
chmod +x scripts/deploy_light.sh
./scripts/deploy_light.sh
```

**Windows:**
```powershell
.\scripts\windows\deploy-light.ps1
```

Скрипт сам: пропишет в `.env` строгий офлайн + пропуск cve-bin-tool + имя
проекта, загрузит образы из `bundle/`, зальёт базы Grype/Trivy в docker-тома и
активирует снимок Grype.

---

## 3. Поставить зависимости GUI и запустить

**Linux:**
```bash
python3 -m pip install fastapi "uvicorn[standard]" python-multipart
python3 -m resilient_updates.cli dashboard --repo-root . --port 8088
```

**Windows:**
```powershell
python -m pip install fastapi "uvicorn[standard]" python-multipart
python -m resilient_updates.cli dashboard --repo-root . --port 8088
```

> Важно: ставь пакеты тем же интерпретатором, которым запускаешь (`python -m pip`,
> а не голый `pip`) — иначе будет ошибка `dashboard requires uvicorn`.
> Если порт 8088 занят/запрещён — возьми другой (`--port 8090`).

---

## 4. Анализ артефакта

1. Открой в браузере **http://127.0.0.1:8088**
2. Перетащи артефакт (`.tar.gz` / `.zip` / `.apk` / `.exe`) в зону загрузки —
   анализ начнётся сам.
3. Стадии Extract → SBOM → Grype → Trivy → Report идут в реальном времени
   (cve-bin-tool в лёгкой сборке пропускается — это норма).
4. Отчёт появится в:
   - `artifacts/reports/final/cve_analysis_report_generated_ru.md` — читать это
   - `artifacts/reports/final/index.html` — открыть в браузере
   - `artifacts/reports/{grype,trivy}/report.json` — сырые данные

---

## Если что-то пошло не так

- **`bundle/` пустой или файлы по ~130 байт** → не установлен/не сработал git-lfs:
  `git lfs install && git lfs pull`.
- **`deploy` ругается на демон/порт** → Docker не запущен; запусти Docker Desktop / `docker`.
- **`dashboard requires uvicorn`** → ставь зависимости через `python -m pip` тем же python.
- **Скан красный на стадии** → открой панель «Процесс анализа», скопируй красный
  блок лога и пришли — разберём.

Подробнее про сборку/передачу бандла — `docs/SHIP_AND_DEPLOY.md`.
