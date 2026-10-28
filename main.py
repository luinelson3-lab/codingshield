#!/usr/bin/env python3
"""
Кодинг-Щит — локальный перехватчик команд ИИ-агентов (MVP).

Примеры запуска:

    python main.py "rm -rf /"
    python main.py --agent Cursor --project-id my-proj "git push --force"
    CODINGSHIELD_AGENT="Claude Code" python main.py -- "npm install"
    python main.py --offline --no-color "DROP TABLE users;"

Коды выхода:
    0 — команда разрешена (или пользователь подтвердил ASK)
    1 — команда заблокирована политикой либо отклонена пользователем
    2 — ошибка конфигурации (policy.yaml не найден / битый)
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence
import yaml
import requests                # <--- ДОБАВИТЬ ЭТУ СТРОКУ
from datetime import datetime  # <--- ДОБАВИТЬ ЭТУ СТРОКУ

from shield_api import ShieldClient, ShieldEvent



# --------------------------------------------------------------------------- #
#  Константы
# --------------------------------------------------------------------------- #
SEVERITY: dict[str, int] = {"ALLOW": 0, "ASK": 1, "BLOCK": 2}

EXIT_ALLOWED = 0
EXIT_BLOCKED = 1

# --- ВСТАВИТЬ НАЧИНАЯ ОТСЮДА ---

API_URL = "https://functions.poehali.dev/16c055d0-cb1f-491e-8093-924e98ad37ac"
API_KEY = "test_project_key_123" 

def send_event_to_server(command: str, status: str, reason: str = ""):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "agent_name": "CLI Interceptor",
        "command": command,
        "status": status,
        "risk_level": "high" if status == "BLOCKED" else "low",
        "reason": reason
    }
    try:
        response = requests.post(API_URL, json=payload, headers=headers, timeout=5)
        print(f"\n[DEBUG] Сервер ответил: {response.status_code} | Текст: {response.text}")
    except Exception as e:
        print(f"\n[DEBUG] Ошибка сети: {e}")

# --- КОНЕЦ ВСТАВКИ ---

# Дальше у вас, скорее всего, начинаются классы или функция main()
EXIT_CONFIG_ERROR = 2

DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.yaml")
DEFAULT_URL = "https://codingshield.ru/api/events"

log = logging.getLogger("codingshield")


# --------------------------------------------------------------------------- #
#  ANSI-цвета (с уважением к NO_COLOR и не-TTY)
# --------------------------------------------------------------------------- #
class Color:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def paint(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{color}{text}{Color.RESET}"


# --------------------------------------------------------------------------- #
#  Модель политики
# --------------------------------------------------------------------------- #
class PolicyError(Exception):
    """Ошибка чтения/валидации policy.yaml."""


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern[str]
    action: str
    description: str = ""


@dataclass(frozen=True)
class Policy:
    default_action: str
    rules: list[Rule]
    server: dict[str, Any]
    project: dict[str, Any]
    send_all: bool


_FLAG_MAP: dict[str, int] = {
    "IGNORECASE": re.IGNORECASE,
    "I": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "M": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "S": re.DOTALL,
}


def _parse_flags(raw: Any, rule_id: str) -> int:
    """Превращает ['IGNORECASE', 'MULTILINE'] (или строку) в битовую маску re."""
    if raw is None:
        return 0
    if isinstance(raw, str):
        raw = re.split(r"[|,\s]+", raw)

    flags = 0
    for item in raw:
        if not item:
            continue
        key = str(item).strip().upper()
        if key not in _FLAG_MAP:
            raise PolicyError(f"Правило '{rule_id}': неизвестный флаг regex '{item}'")
        flags |= _FLAG_MAP[key]
    return flags


def load_policy(path: Path) -> Policy:
    """Читает и валидирует файл политики."""
    if not path.is_file():
        raise PolicyError(f"Файл политики не найден: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"Не удалось распарсить {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyError("Корень policy.yaml должен быть словарём")

    default_action = str(raw.get("default_action", "ALLOW")).upper()
    if default_action not in SEVERITY:
        raise PolicyError(
            f"default_action='{default_action}' недопустим (ALLOW|ASK|BLOCK)"
        )

    rules: list[Rule] = []
    for idx, item in enumerate(raw.get("rules") or []):
        if not isinstance(item, dict):
            raise PolicyError(f"Правило #{idx} должно быть словарём")
        if item.get("enabled", True) is False:
            continue

        rule_id = str(item.get("id") or f"rule-{idx}")
        pattern_src = item.get("pattern")
        if not pattern_src:
            raise PolicyError(f"Правило '{rule_id}': отсутствует 'pattern'")

        action = str(item.get("action", "ASK")).upper()
        if action not in SEVERITY:
            raise PolicyError(
                f"Правило '{rule_id}': action='{action}' недопустим (ALLOW|ASK|BLOCK)"
            )

        try:
            compiled = re.compile(
                str(pattern_src), _parse_flags(item.get("flags"), rule_id)
            )
        except re.error as exc:
            raise PolicyError(f"Правило '{rule_id}': битый regex — {exc}") from exc

        rules.append(
            Rule(
                id=rule_id,
                pattern=compiled,
                action=action,
                description=str(item.get("description", "")).strip(),
            )
        )

    return Policy(
        default_action=default_action,
        rules=rules,
        server=dict(raw.get("server") or {}),
        project=dict(raw.get("project") or {}),
        send_all=bool((raw.get("logging") or {}).get("send_all", True)),
    )


# --------------------------------------------------------------------------- #
#  Редaктирование секретов перед отправкой на сервер
# --------------------------------------------------------------------------- #
_REDACTION_RULES: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?i)(--?(?:password|passwd|pwd|token|secret|api[_-]?key|apikey)"
            r"[=\s]+)(\S+)"
        ),
        r"\1***",
    ),
    (re.compile(r"\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{20,}\b"), "***"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), "***"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "***"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "***"),
    (
        re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)(\S+)"),
        r"\1***",
    ),
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"), "://***:***@"),
]


def redact(command: str) -> str:
    """Маскирует потенциальные секреты, чтобы не утекали в логи/на сервер."""
    result = command
    for pattern, replacement in _REDACTION_RULES:
        result = pattern.sub(replacement, result)
    return result


# --------------------------------------------------------------------------- #
#  Движок вычисления решения
# --------------------------------------------------------------------------- #
@dataclass
class Decision:
    action: str                       # ALLOW | ASK | BLOCK
    matched: list[Rule]

    @property
    def primary_rule(self) -> Rule | None:
        if not self.matched:
            return None
        return max(self.matched, key=lambda r: SEVERITY[r.action])


def evaluate(command: str, policy: Policy) -> Decision:
    """Прогоняет команду по всем правилам, возвращает итоговое решение."""
    matched = [rule for rule in policy.rules if rule.pattern.search(command)]

    final = policy.default_action
    for rule in matched:
        if SEVERITY[rule.action] > SEVERITY[final]:
            final = rule.action

    return Decision(action=final, matched=matched)


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codingshield",
        description="Кодинг-Щит — локальный перехватчик команд ИИ-агентов.",
        epilog='Пример: python main.py --agent "Claude Code" -- "git push --force"',
    )
    parser.add_argument(
        "--policy",
        default=str(DEFAULT_POLICY_PATH),
        help="Путь к policy.yaml (по умолчанию рядом со скриптом).",
    )
    parser.add_argument("--agent", default=None, help="Имя ИИ-агента.")
    parser.add_argument("--project-id", default=None, help="ID проекта.")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Не отправлять события на сервер (только локальная проверка).",
    )
    parser.add_argument(
        "--exec",
        dest="execute",
        action="store_true",
        help="Выполнить команду после одобрения (по умолчанию — только проверка).",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Автоматически подтверждать запросы ASK (использовать осторожно!).",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Отключить ANSI-раскраску."
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Меньше вывода."
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Команда для проверки. Используйте `--` перед командой.",
    )
    return parser


def _setup_logging(quiet: bool) -> None:
    logging.basicConfig(
        level=logging.ERROR if quiet else logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )


def _color_enabled(args: argparse.Namespace) -> bool:
    if args.no_color or os.getenv("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty()


def _ask_user(decision: Decision, command: str, use_color: bool) -> bool:
    """Интерактивное подтверждение для ASK. Возвращает True, если одобрено."""
    reasons = "\n".join(
        f"   • [{r.id}] {r.description or 'без описания'}"
        for r in decision.matched
        if r.action == "ASK"
    )
    print(
        paint("⚠️  Кодинг-Щит: команда требует подтверждения.", Color.YELLOW, use_color)
    )
    if reasons:
        print(reasons)
    print(f"   Команда: {paint(command, Color.DIM, use_color)}")

    try:
        answer = input("   Выполнить? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False

    return answer in {"y", "yes", "д", "да"}


def _send_event(
    policy: Policy,
    command: str,
    status: str,
    agent: str,
    project_id: str,
    decision: Decision,
    offline: bool,
) -> None:
    """Отправляет событие на сервер (если нужно и если не offline)."""
    if offline:
        return
    if not policy.send_all and status == "ALLOWED":
        return

    url = os.getenv("CODINGSHIELD_URL") or policy.server.get("url") or DEFAULT_URL
    api_key = os.getenv("CODINGSHIELD_API_KEY") or policy.server.get("api_key") or None

    primary = decision.primary_rule
    event = ShieldEvent(
        command=redact(command),
        status=status,
        agent=agent,
        project_id=project_id,
        rule_id=primary.id if primary else None,
        rule_description=primary.description if primary and primary.description else None,
    )

    with ShieldClient(
        url=url,
        timeout=policy.server.get("timeout", 3.0),
        retries=policy.server.get("retries", 2),
        api_key=api_key,
    ) as client:
        client.send(event)


def _run_command(command: str) -> int:
    """Выполняет команду в shell и возвращает её код возврата."""
    log.debug("Выполняю: %s", command)
    completed = subprocess.run(command, shell=True, check=False)  # noqa: S602
    return completed.returncode


# --------------------------------------------------------------------------- #
#  main
# --------------------------------------------------------------------------- #
def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.quiet)
    use_color = _color_enabled(args)

    # --- 1. Собираем команду -------------------------------------------------
    parts = list(args.command)
    if parts and parts[0] == "--":
        parts = parts[1:]
    command = " ".join(parts).strip()

    if not command:
        print("Ошибка: команда не передана.", file=sys.stderr)
        print('Пример: python main.py -- "rm -rf /"', file=sys.stderr)
        return EXIT_CONFIG_ERROR

    # --- 2. Загружаем политику ----------------------------------------------
    try:
        policy = load_policy(Path(args.policy))
    except PolicyError as exc:
        # Fail-closed: битая политика = не пропускаем команду наугад.
        print(paint(f"🛑 Ошибка конфигурации Кодинг-Щита: {exc}", Color.RED, use_color),
              file=sys.stderr)
        return EXIT_CONFIG_ERROR

    # --- 3. Определяем метаданные -------------------------------------------
    agent = (
        args.agent
        or os.getenv("CODINGSHIELD_AGENT")
        or str(policy.project.get("agent") or "Unknown Agent")
    )
    project_id = (
        args.project_id
        or os.getenv("CODINGSHIELD_PROJECT_ID")
        or str(policy.project.get("id") or "unknown-project")
    )

    # --- 4. Проверяем --------------------------------------------------------
    decision = evaluate(command, policy)

    # --- 5. Обрабатываем ASK -------------------------------------------------
    if decision.action == "ASK":
        approved = args.yes or _ask_user(decision, command, use_color)
        if not approved:
            status = "DENIED"
            _send_event(policy, command, status, agent, project_id, decision, args.offline)
            print(
                paint("🛑 Команда отклонена пользователем Кодинг-Щитом.",
                      Color.RED, use_color)
            )
            return EXIT_BLOCKED

    # --- 6. Определяем финальный статус и логируем ---------------------------
    if decision.action == "BLOCK":
        status = "BLOCKED"
    elif decision.action == "ASK":
        status = "ASKED"      # подтверждено пользователем
    else:
        status = "ALLOWED"

    _send_event(policy, command, status, agent, project_id, decision, args.offline)

    # --- 7. Реагируем --------------------------------------------------------
    if decision.action == "BLOCK":
        primary = decision.primary_rule
        reason = f" ({primary.id}: {primary.description})" if primary else ""
        print(
            paint(f"🛑 Команда заблокирована Кодинг-Щитом!{reason}",
                  Color.RED, use_color)
        )
        send_event_to_server(command, status="BLOCKED", reason=str(reason))
        return EXIT_BLOCKED

    if not args.quiet:
        if decision.action == "ASK":
            print(paint("✅ Команда подтверждена.", Color.GREEN, use_color))
        else:
            print(paint("✅ Команда разрешена Кодинг-Щитом.", Color.GREEN, use_color))
        send_event_to_server(command, status="ALLOWED")
    # --- 8. (Опционально) реально выполняем ----------------------------------
    if args.execute:
        return _run_command(command)

    return EXIT_ALLOWED


if __name__ == "__main__":
    raise SystemExit(main())