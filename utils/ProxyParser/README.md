# ProxyParser

Сборщик прокси Telegram. Обходит открытые списки, каналы t.me, форумы и
GitHub-репозитории, вытаскивает прокси, убирает дубли и записывает их в
`proxy.md` — **одна ссылка `tg://` на строку**, готовую к импорту в Telegram.

Это отдельная, самостоятельная программа. Всё нужное лежит внутри папки:
настроек, соседних пакетов и базы данных не требуется.

```
python utils/ProxyParser/app.py          # -> utils/ProxyParser/proxy.md
```

## Что нужно

```bash
pip install aiohttp tqdm cryptography
```

- `aiohttp` — загрузка страниц;
- `tqdm` — полоса прогресса;
- `cryptography` (или `pycryptodome`) — два источника отдают списки,
  зашифрованные AES-GCM; без этой библиотеки они просто пропустятся.

Проверено на Python 3.14. Остальное — стандартная библиотека.

## Запуск

```bash
python utils/ProxyParser/app.py                        # все источники из config.py -> proxy.md
python utils/ProxyParser/app.py -o list.txt            # свой файл
python utils/ProxyParser/app.py -u https://t.me/s/mtp4tg   # свой источник
python utils/ProxyParser/app.py --no-anonymizers       # быстрее: без обходных маршрутов
python utils/ProxyParser/app.py --json --indent 2      # JSON в stdout, файл не создаётся
python utils/ProxyParser/app.py -q                     # без полосы прогресса
python utils/ProxyParser/app.py --help                 # все ключи

python -m utils.ProxyParser --json         # то же из корня проекта
```

### Ключи запуска

| Ключ | По умолчанию | Что делает |
|---|---|---|
| `-o`, `--out FILE` | `utils/ProxyParser/proxy.md` | куда писать список |
| `-u`, `--url URL` | все из `config.py` | свой источник, можно повторять |
| `-c`, `--concurrency N` | 8 | одновременных загрузок |
| `-d`, `--deadline SEC` | 60 | бюджет времени на один источник |
| `-t`, `--timeout SEC` | 4 | таймаут одного запроса |
| `--no-anonymizers` | выкл | не ходить через allorigins/jina/Wayback |
| `--keep-web` | выкл | оставить и `http://`-прокси |
| `--json` | выкл | напечатать JSON в stdout вместо файла |
| `--indent N` | без отступов | отступ в JSON |
| `-q`, `--quiet` | выкл | без полосы прогресса |

Код возврата: `0`, если нашлись прокси, `1`, если список пуст.

## Формат результата

```
tg://proxy?server=185.84.156.43&port=444&secret=dd41b712fe12019c64e281bcb6aeccded7
tg://proxy?server=158.160.204.45&port=443&secret=dd6dc6c32df732ff33148c4217aa901c4d
tg://socks?server=91.196.178.98&port=1080
```

- UTF-8, перевод строки `\n` (не CRLF), файл перезаписывается целиком;
- без заголовков и разметки — можно скормить клиенту или читать построчно;
- дубли убраны, порядок стабильный: тип → хост → порт → секрет.

`http://`-прокси по умолчанию отбрасываются: Telegram импортирует только
`tg://`. Чтобы оставить их — `--keep-web`.

## Как это работает

```
config.py         список источников и таймауты
collecting/       сеть: http.py (запрос, ретраи, обходные маршруты),
                  sources.py (зеркала, Wayback, прокрутка t.me, пагинация
                  4pda, inline-JS, AES-GCM), collector.py (пул потоков)
parsing/          разбор текста в прокси: Proxy, parse, crypto
utils/            stages.py (прогресс и логи), report.py (запись файла)
app.py            точка входа
__init__.py       библиотечный API
```

Каждый источник получает свой поток, свою aiohttp-сессию и жёсткий бюджет
времени (`-d`). Источник не может задержать прогон: пустой ответ,
зависший хост или битая пагинация обрываются по таймауту, а не висят.

Подробности по каждому источнику пишутся в
`utils/ProxyParser/logs/<timestamp>_collect.log` — в консоль попадают только
полоса прресса и итог.

## Использование как библиотека

```python
from utils import ProxyParser

data = ProxyParser.collect()          # dict со статистикой и списком
print(data["count"])                  # сколько прокси
print(data["proxies"][0])             # первая ссылка

ProxyParser.collect(urls=["https://t.me/s/mtp4tg"],   # свои источники
                    deadline=30,
                    use_anonymizers=False)

# только список ссылок, без статистики
links = ProxyParser.collect_proxies(urls=["https://t.me/s/mtp4tg"])

print(ProxyParser.to_json(data, indent=2))            # JSON-строка
ProxyParser.write_lines("proxy.md", links)            # записать файл
```

`data` сериализуется в JSON без преобразований:

```json
{
  "count": 5894,
  "proxies": ["tg://proxy?server=…"],
  "types": {"MTPROTO": 5869, "SOCKS5": 25, "WEB": 21},
  "dropped_non_tg": 21,
  "duplicates": 28014,
  "sources": {"total": 61, "ok": 57, "empty": 4, "no_new": 2},
  "elapsed_sec": 76.0,
  "generated_at": "2026-10-02T02:39:44+03:00"
}
```

`count` — длина `proxies`. Типы в `types` считаются по всем найденным
прокси, включая отброшенные `http://`, поэтому `types` может не
сходиться с `count` — это нормально.

Полный прогон обычно занимает 1–3 минуты, но сеть и источники живут своей
жизнью: конкретные числа каждый раз другие.

## Чего программа не делает

- **Не проверяет прокси.** В списке есть мёртвые и отключённые адреса —
  их отсеивает этап TCP-проверки в основном проекте
  (`python main.py`, пакеты `utils/TcpChecker` и `utils/ProxyDatabase`).
- **Не пишет в базу.** SQLite в этой программе нет вообще.
- **Не гарантирует полноту.** Часть источников может быть недоступна из
  вашей сети; смотрите `sources.empty` в JSON или лог.

## Если что-то пошло не так

| Симптом | Что делать |
|---|---|
| `Записано прокси: 0` | сеть блокирует источники; попробуйте без `--no-anonymizers` или свой `-u` |
| прогон идёт дольше ожидаемого | уменьшить `-d 20`, поднять `-c 16` |
| `ModuleNotFoundError: aiohttp` | `pip install aiohttp tqdm` |
| список пустой, а лог есть | открыть `utils/ProxyParser/logs/<timestamp>_collect.log` — там видно, что ответил каждый источник |
| нужен быстрый точечный сбор | `python utils/ProxyParser/app.py -u <url> --no-anonymizers -d 25 -q` |