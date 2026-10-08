"""Прогресс и логирование этапов.

Консоль получает только полосу прогресса и итог; все подробности уходят в
``logs/<timestamp>_<stage>.log``. Обёртка ``stage`` — контекст-менеджер,
внутри доступен ``st.bar`` (tqdm) и ``st.log`` (писатель в файл).
"""

import os
from datetime import datetime
from typing import Optional

from tqdm import tqdm

from utils.ProxyParser import config

__all__ = ["LogFile", "stage"]


def _open_log(log_name: str) -> tuple:
    """Создаёт logs/<timestamp>_<log_name>, возвращает (путь, файловый объект)."""
    os.makedirs(config.LOGS_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(config.LOGS_DIR, f"{stamp}_{log_name}")
    return path, open(path, "a", encoding="utf-8", newline="\n")


class LogFile:
    """Дублирует сообщения в файл лога и, при echo, в консоль."""

    def __init__(self, name: str, echo: bool = False):
        self.path, self._fh = _open_log(name)
        self.echo = echo

    def __call__(self, msg: str) -> None:
        self._fh.write(f"{datetime.now():%H:%M:%S} {msg}\n")
        self._fh.flush()
        if self.echo:
            print(msg, flush=True)

    def section(self, title: str) -> None:
        self(f"{'-' * 60}\n>>> {title}\n{'-' * 60}")

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass

    def __enter__(self) -> "LogFile":
        return self

    def __exit__(self, *exc):
        self.close()


class _CallableLog:
    """Адаптер: этап принимает и LogFile, и голый callable (``log.append``).

    Нужен потому, что ``stage`` ждёт объект с ``section()`` и ``path``, а
    вызывающий код часто держит просто функцию записи.
    """

    def __init__(self, fn, path: str = "(внешний лог)"):
        self._fn = fn
        self.path = path

    def __call__(self, msg: str) -> None:
        self._fn(msg)

    def section(self, title: str) -> None:
        self(f"{'-' * 60}\n>>> {title}\n{'-' * 60}")

    def close(self) -> None:
        pass


class stage:
    """Контекст-менеджер одного этапа: заголовок, прогресс, итог, лог-файл.

    Готовый лог можно передать снаружи — тогда свой файл не создаётся и
    внешний лог не закрывается вместе с этапом.
    """

    def __init__(self, number: int, title: str, total: Optional[int] = None,
                 unit: str = "it", log_name: str = "stage.log",
                 quiet: bool = False, log=None, postfix: str = ""):
        self.number = number
        self.title = title
        self.total = total
        self.unit = unit
        self.quiet = quiet
        self.postfix = postfix
        if log is None:
            self._own_log = True
            self.log = LogFile(log_name)
        else:
            self._own_log = False
            self.log = log if isinstance(log, LogFile) else _CallableLog(log)

    def __enter__(self) -> "stage":
        label = f"[Этап {self.number}] {self.title}"
        self.log.section(f"{label} — всего "
                         f"{self.total if self.total is not None else '?'}")
        if not self.quiet:
            print(f"\n{label}", flush=True)
        # leave=True: без него последняя строка полосы остаётся в буфере
        # stdout и «всплывает» в конце прогона вместе со сводкой.
        self.bar = tqdm(total=self.total, unit=self.unit, leave=True,
                        disable=self.quiet, dynamic_ncols=True,
                        mininterval=0.2, postfix=self.postfix,
                        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} "
                                   "[{elapsed}<{remaining}] {postfix}")
        return self

    def set_postfix(self, text: str, refresh: bool = True) -> None:
        self.bar.set_postfix_str(text, refresh=refresh)

    def close(self, summary: str = "") -> None:
        if summary:
            self.log(f"Итог этапа {self.number}: {summary}")
        if self.quiet:
            if self._own_log:
                self.log.close()
            return
        self.bar.set_postfix_str(summary[:60], refresh=False)
        self.bar.close()
        print(f"   {summary}", flush=True)
        print(f"   лог: {self.log.path}", flush=True)
        if self._own_log:
            self.log.close()

    def __exit__(self, *exc):
        self.bar.close()
        if self._own_log:
            self.log.close()