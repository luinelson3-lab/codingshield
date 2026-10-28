"""
Модуль отправки событий на сервер Кодинг-Щита.

Философия модуля — FAIL-SAFE:
    любая ошибка сети/сервера НЕ должна ломать рабочее окружение агента.
    Мы логируем проблему и возвращаем False, а не выбрасываем исключение
    наверх (блокирующее решение уже принято локально).
"""

from __future__ import annotations

import getpass
import logging
import socket
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import requests

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
#  Модель события
# --------------------------------------------------------------------------- #
@dataclass
class ShieldEvent:
    """Одно событие проверки команды."""

    command: str
    status: str                       # ALLOWED | ASKED | DENIED | BLOCKED
    agent: str
    project_id: str
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    exit_code: Optional[int] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_payload(self) -> dict[str, Any]:
        """Сериализует событие в JSON-совместимый dict (без None-полей)."""
        data = asdict(self)
        data["hostname"] = _safe_hostname()
        data["user"] = _safe_user()
        return {k: v for k, v in data.items() if v is not None}


def _safe_hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except (OSError, KeyError):
        return "unknown"


# --------------------------------------------------------------------------- #
#  HTTP-клиент
# --------------------------------------------------------------------------- #
class ShieldClient:
    """Минималистичный клиент с ретраями и защитой от падений."""

    def __init__(
        self,
        url: str,
        timeout: float = 3.0,
        retries: int = 2,
        api_key: str | None = None,
    ) -> None:
        self.url = url
        self.timeout = float(timeout)
        self.retries = max(0, int(retries))

        self._session = requests.Session()
        self._session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "CodingShield-Agent/0.1 (+python-requests)",
            }
        )
        if api_key:
            self._session.headers["Authorization"] = f"Bearer {api_key}"

    # ------------------------------------------------------------------ API
    def send(self, event: ShieldEvent) -> bool:
        """Отправляет событие. Возвращает True при 2xx-ответе.

        Никогда не бросает исключений наружу.
        """
        payload = event.to_payload()

        for attempt in range(self.retries + 1):
            try:
                response = self._session.post(
                    self.url, json=payload, timeout=self.timeout
                )

                if 200 <= response.status_code < 300:
                    log.debug("Событие отправлено: HTTP %s", response.status_code)
                    return True

                # 4xx — проблема на нашей стороне, повторять бессмысленно
                if response.status_code < 500:
                    log.warning(
                        "Сервер отклонил событие: HTTP %s (%s)",
                        response.status_code,
                        response.text[:200],
                    )
                    return False

                log.warning("Сервер вернул HTTP %s, повтор...", response.status_code)

            except requests.RequestException as exc:
                log.warning(
                    "Сетевая ошибка при отправке (попытка %d/%d): %s",
                    attempt + 1,
                    self.retries + 1,
                    exc,
                )

            # Экспоненциальная пауза между попытками
            if attempt < self.retries:
                time.sleep(0.5 * (2 ** attempt))

        log.error("Не удалось отправить событие на %s", self.url)
        return False

    # ------------------------------------------------------------------ cleanup
    def close(self) -> None:
        try:
            self._session.close()
        except Exception:  # noqa: BLE001 — закрытие не должно падать
            pass

    # Контекстный менеджер — удобно использовать `with ShieldClient(...) as c:`
    def __enter__(self) -> "ShieldClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()