# Большие артефакты (гигабайтные): доставка, регистрация, скан

Веб-загрузка через морду годится для файлов до нескольких сотен МБ. Для
гигабайтных артефактов (3–10 ГБ и больше) она **не рекомендуется**: у браузера
нет докачки (обрыв на 90% = всё заново), uvicorn складывает загрузку во
временный файл (двойное место), а VPN-каналы рвутся.

Рабочая схема для больших файлов — три шага:

```
1. доставить файл на сервер (rsync / WinSCP / scp)
2. зарегистрировать его в каталоге БЕЗ загрузки (hardlink, 0 лишних байт)
3. запустить скан — с карточки в морде или флагом -s
```

Проверено на артефакте 3.4 ГБ: доставка 5,5 мин (rsync, ~10 МБ/с через VPN),
регистрация мгновенная, полный скан ~4 мин, файл занимает место на диске
**один раз** независимо от числа прогонов.

## Шаг 1 — доставка на сервер

Целевой каталог — `/home/SCA/_incoming/<CYBERSEC-XXXXX>/` (создать при
необходимости). Он на той же файловой системе, что и каталог артефактов, —
это важно для hardlink-регистрации.

### Вариант А: rsync (рекомендуется — докачка после обрыва)

Из WSL / Linux / Git Bash:

```bash
rsync -e "ssh -i ~/.ssh/<приватный-ключ> -o IdentitiesOnly=yes" \
      --partial --append-verify --info=progress2 \
      /путь/к/artifact.gz \
      yuriy.tumanov@10.2.108.47:/home/SCA/_incoming/CYBERSEC-XXXXX/
```

- `--partial --append-verify` — после обрыва канала перезапусти ту же команду:
  докачает с места разрыва, сверив уже переданный кусок контрольной суммой.
- rsync на сервере установлен (`sudo dnf install rsync`, внутреннее зеркало
  RedOS).
- Если прямой маршрут (FortiClient VPN) лежит, добавь прыжок:
  `-e "ssh -J <jump-host> -i ~/.ssh/<ключ> ..."`.

### Вариант Б: WinSCP (GUI, докачка встроена)

Прямое подключение (FortiClient VPN поднят):

1. **New Site**: протокол `SFTP`, Host name `10.2.108.47`, порт `22`,
   User name `yuriy.tumanov`, пароль пустой.
2. **Advanced → SSH → Authentication → Private key file**: выбери
   **приватный** ключ (файл `elaria_rostel` *без* расширения; в диалоге выбора
   поставь фильтр «All files»). Файл `.pub` не подойдёт — это публичная
   половина. WinSCP предложит сконвертировать ключ в свой формат `.ppk` —
   соглашайся, он сохранит копию рядом.
3. **Advanced → Connection → Tunnel**: галку «Connect through SSH tunnel»
   **снять** — туннель нужен только для запасного маршрута через промежуточный
   хост (тогда в Tunnel указывается тот хост и его ключ, а основная сессия
   остаётся `10.2.108.47`).
4. Отдельно настраивать MAC (`-m hmac-sha2-256` из OpenSSH-однострочника) не
   нужно: PuTTY-ядро WinSCP договаривается об этом алгоритме само.
5. Докачка больших файлов включена по умолчанию:
   Preferences → Transfer → Endurance → «Enable transfer resume /
   transfer to temporary filename» (порог 100 КБ).

Эквивалент консольного подключения, с которого списаны эти настройки:

```text
ssh -m hmac-sha2-256 -i C:\Users\<user>\.ssh\elaria_rostel yuriy.tumanov@10.2.108.47
```

### Вариант В: scp (одним куском, без докачки)

```bash
scp -i ~/.ssh/<ключ> /путь/к/artifact.gz \
    yuriy.tumanov@10.2.108.47:/home/SCA/_incoming/CYBERSEC-XXXXX/
```

Годится для стабильного канала; при обрыве начинает заново.

После доставки сверь контрольную сумму с источником:

```bash
# локально                                  # на сервере
sha256sum artifact.gz                       sha256sum /home/SCA/_incoming/.../artifact.gz
```

## Шаг 2 — регистрация в каталоге (без HTTP-загрузки)

На сервере, из корня репозитория:

```bash
cd /home/SCA/el-sca-ansamble
scripts/register_local_artifact.sh \
  -f /home/SCA/_incoming/CYBERSEC-13529/artifact.gz \
  -c CYBERSEC-13529 \
  -s        # сразу запустить скан (опционально)
```

Что делает скрипт:

- **hardlink** файла в `artifacts/uploads/artifact-<ts>-<id>/` — та же файловая
  система, поэтому 0 лишних байт (если ФС другая — автоматически копия);
- считает sha1+sha256 и пишет `artifact.json` в том же формате, что и обычная
  загрузка через морду (`ArtifactCatalog.create_upload`), поэтому карточка
  полноценная: Scan, Reports, переименование, CYBERSEC-тег, «Удалить навсегда»;
- с флагом `-s` дёргает `POST /api/artifacts/<id>/scan` — тот же пайплайн, что
  и кнопка Scan.

Замечание про место: начиная с фикса `ccc9a87` оркестратор тоже **линкует**
входы ≥ 512 МиБ в `_SCA_reports/<run>/input/` вместо копирования. Итого файл
любого размера лежит на диске один раз (`_incoming` + `uploads` + все раны
указывают на один inode). «Удалить навсегда» с карточки убирает только ссылку
из `uploads`; мастер-копия в `_incoming` и evidence в ранах не трогаются.

## Шаг 3 — скан и отчёты

- Скан: кнопка **Scan** на карточке, либо флаг `-s` при регистрации, либо
  вручную: `curl -X POST http://127.0.0.1:8088/api/artifacts/<id>/scan`.
- Отчёты: кнопка **Reports** (открывает свежайший ран артефакта), список ранов
  на `/runs`, Markdown — `GET /api/runs/<run-id>/report.md`.
- В отчёте проверяй блок «Объект анализа»: имя файла, CYBERSEC-id и полный
  набор хэшей (MD5 + SHA-1 + SHA-256 для входного архива и распакованной цели);
  sha256 входа должен совпасть с тем, что ты считала при доставке.

## Совсем руками (если скрипт недоступен)

```bash
cd /home/SCA/el-sca-ansamble
TS=$(date -u +%Y%m%d-%H%M%S); AID="artifact-$TS-$(head -c3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
mkdir -p "artifacts/uploads/$AID"
ln /home/SCA/_incoming/CYBERSEC-13529/artifact.gz "artifacts/uploads/$AID/artifact.gz"
SHA256=$(sha256sum "artifacts/uploads/$AID/artifact.gz" | cut -d' ' -f1)
SHA1=$(sha1sum   "artifacts/uploads/$AID/artifact.gz" | cut -d' ' -f1)
SIZE=$(stat -c %s "artifacts/uploads/$AID/artifact.gz")
cat > "artifacts/uploads/$AID/artifact.json" <<EOF
{
  "id": "$AID",
  "kind": "uploaded",
  "original_filename": "artifact.gz",
  "stored_filename": "artifact.gz",
  "stored_path": "/home/SCA/el-sca-ansamble/artifacts/uploads/$AID/artifact.gz",
  "display_name": "artifact",
  "case_id": "CYBERSEC-13529",
  "sha1": "$SHA1",
  "sha256": "$SHA256",
  "size": $SIZE,
  "uploaded_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)",
  "deleted_at": "",
  "runs": []
}
EOF
curl -X POST "http://127.0.0.1:8088/api/artifacts/$AID/scan"
```

Поля — точная копия того, что пишет `create_upload`; после этого карточка
появляется в морде как обычная.
