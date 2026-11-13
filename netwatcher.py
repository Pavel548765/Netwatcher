#!/usr/bin/env python3

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────────────────────
# Загрузка пользовательской конфигурации из /etc/netwatcher/data.py
# ─────────────────────────────────────────────────────────────────────────────
CONFIG_DIR = os.environ.get("NETWATCHER_CONFIG_DIR", "/etc/netwatcher")
if CONFIG_DIR not in sys.path:
    sys.path.insert(0, CONFIG_DIR)

try:
    import data as CONFIG  # type: ignore
except ImportError as exc:
    print(
        f"FATAL: не удалось загрузить конфигурацию из {CONFIG_DIR}/data.py: {exc}",
        file=sys.stderr,
    )
    sys.exit(2)


# ─────────────────────────────────────────────────────────────────────────────
# Константы из data.py
# ─────────────────────────────────────────────────────────────────────────────
LOG_DIR    = getattr(CONFIG, "LOG_DIR",    "/var/log/netwatcher")
LOG_FILE   = getattr(CONFIG, "LOG_FILE",   os.path.join(LOG_DIR, "netwatcher.log"))
STATE_FILE = getattr(CONFIG, "STATE_FILE", os.path.join(LOG_DIR, "state.json"))

CHECK_URLS: List[str]  = getattr(CONFIG, "CHECK_URLS", [])
URL_TEST_TARGET: str   = getattr(CONFIG, "URL_TEST_TARGET", CHECK_URLS[0] if CHECK_URLS else "")

TCPING_BIN: str = getattr(CONFIG, "TCPING_BIN", "tcping")
CURL_BIN: str   = getattr(CONFIG, "CURL_BIN",   "curl")
UCI_BIN: str    = getattr(CONFIG, "UCI_BIN",    "uci")
LUA_BIN: str    = getattr(CONFIG, "LUA_BIN",    "lua")

TCPING_TIMEOUT:    int = getattr(CONFIG, "TCPING_TIMEOUT",    5)
CURL_TIMEOUT:      int = getattr(CONFIG, "CURL_TIMEOUT",      10)
NET_CMD_TIMEOUT:   int = getattr(CONFIG, "NET_CMD_TIMEOUT",   30)
SUBSCRIBE_WAIT:    int = getattr(CONFIG, "SUBSCRIBE_WAIT",    45)
INIT_RESTART_WAIT: int = getattr(CONFIG, "INIT_RESTART_WAIT", 8)

PASSWALL2_INIT:    str = getattr(CONFIG, "PASSWALL2_INIT",    "/etc/init.d/passwall2")
SUBSCRIBE_LUA:     str = getattr(CONFIG, "SUBSCRIBE_LUA",     "/usr/share/passwall2/subscribe.lua")
PASSWALL2_PACKAGE: str = getattr(CONFIG, "PASSWALL2_PACKAGE", "passwall2")
PASSWALL2_GLOBAL:  str = getattr(CONFIG, "PASSWALL2_GLOBAL",  "passwall2.@global[0]")
DIRECT_NODE:       str = getattr(CONFIG, "DIRECT_NODE",       "_direct")

MAX_WORKERS: int = getattr(CONFIG, "MAX_WORKERS", 8)

SERVER_BLACKLIST_ADDRESSES: List[str] = getattr(CONFIG, "SERVER_BLACKLIST_ADDRESSES", [])
BLACKLIST_THRESHOLD:    int = getattr(CONFIG, "BLACKLIST_THRESHOLD",    3)
BLACKLIST_DURATION_MIN: int = getattr(CONFIG, "BLACKLIST_DURATION_MIN", 30)

HISTORY_LIMIT: int = getattr(CONFIG, "HISTORY_LIMIT", 100)

# Валидные HTTP-коды для «ресурс ответил корректно».
VALID_REDIRECT_CODES = (301, 302, 307, 308)


# ─────────────────────────────────────────────────────────────────────────────
# Логирование
# ─────────────────────────────────────────────────────────────────────────────
def setup_logging() -> logging.Logger:
    """
    Настраивает корневой логгер скрипта. Уровень всегда INFO.
    Записи идут в файл /var/log/netwatcher/netwatcher.log и в stdout.
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger("netwatcher")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(fmt)
    fh.setLevel(logging.INFO)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh.setLevel(logging.INFO)
    logger.addHandler(sh)

    return logger


logger = setup_logging()


# ─────────────────────────────────────────────────────────────────────────────
# Утилиты общего назначения
# ─────────────────────────────────────────────────────────────────────────────
def _fmt_ms(value: Optional[float]) -> str:
    """Форматирование миллисекунд для логов: 'n/a' или 'X.Xms'."""
    return f"{value:.1f}ms" if value is not None else "n/a"


def _extract_host_port(url: str) -> Tuple[str, int]:
    """
    Возвращает (host, port) из URL. По умолчанию 443 для https, 80 для http.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def run_command(
    cmd: List[str],
    timeout: Optional[int] = NET_CMD_TIMEOUT,
    check: bool = False,
    capture: bool = True,
) -> subprocess.CompletedProcess:
    """
    Универсальная обёртка над subprocess.run для вызова внешних утилит.

    :param cmd:     список аргументов;
    :param timeout: таймаут в секундах;
    :param check:   если True — исключение при ненулевом коде;
    :param capture: перехватывать stdout/stderr;
    :return:        CompletedProcess.
    """
    pretty = " ".join(cmd)
    logger.debug("run_command: %s", pretty)
    try:
        return subprocess.run(cmd, capture_output=capture, text=True,
                              timeout=timeout, check=check)
    except FileNotFoundError as exc:
        logger.error("Команда не найдена: %s (%s)", pretty, exc)
        raise RuntimeError(f"binary not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        logger.error("Таймаут команды (%ss): %s", timeout, pretty)
        raise RuntimeError(f"command timeout: {pretty}") from exc


def which(binary: str) -> Optional[str]:
    """Абсолютный путь до бинарника или None."""
    return shutil.which(binary)


def validate_config() -> None:
    """
    Проверяет критичные для работы параметры. При отсутствии CHECK_URLS
    скрипт завершается с кодом 2.
    """
    if not CHECK_URLS:
        logger.error("CHECK_URLS в data.py пуст — нечего проверять")
        sys.exit(2)
    if not SERVER_BLACKLIST_ADDRESSES:
        logger.info("SERVER_BLACKLIST_ADDRESSES пуст — статический чёрный список выключен")
    logger.info(
        "Параметры: MAX_WORKERS=%d, BLACKLIST_THRESHOLD=%d, BLACKLIST_DURATION_MIN=%d",
        MAX_WORKERS, BLACKLIST_THRESHOLD, BLACKLIST_DURATION_MIN,
    )


# ─────────────────────────────────────────────────────────────────────────────
# UCI
# ─────────────────────────────────────────────────────────────────────────────
def uci_get(path: str) -> Optional[str]:
    """Читает UCI-параметр, None при отсутствии/ошибке."""
    try:
        res = run_command([UCI_BIN, "-q", "get", path], timeout=10)
    except RuntimeError:
        return None
    if res.returncode != 0:
        return None
    return (res.stdout or "").strip() or None


def uci_set(path: str, value: str) -> bool:
    """Устанавливает UCI-параметр. True при успехе."""
    try:
        res = run_command([UCI_BIN, "set", f"{path}={value}"], timeout=10)
    except RuntimeError:
        return False
    if res.returncode != 0:
        logger.error("uci set %s=%s провалился: %s",
                     path, value, (res.stderr or "").strip())
        return False
    logger.info("UCI: установлено %s=%s", path, value)
    return True


def uci_commit(package: str = PASSWALL2_PACKAGE) -> bool:
    """Фиксирует UCI-изменения для пакета."""
    try:
        res = run_command([UCI_BIN, "commit", package], timeout=10)
    except RuntimeError:
        return False
    if res.returncode != 0:
        logger.error("uci commit %s провалился: %s",
                     package, (res.stderr or "").strip())
        return False
    logger.info("UCI: изменения для '%s' зафиксированы", package)
    return True


def uci_show(package: str = PASSWALL2_PACKAGE) -> str:
    """Полный дамп `uci show <package>`."""
    try:
        res = run_command([UCI_BIN, "show", package], timeout=NET_CMD_TIMEOUT)
    except RuntimeError:
        return ""
    if res.returncode != 0:
        logger.error("uci show %s провалился", package)
        return ""
    return res.stdout or ""


# ─────────────────────────────────────────────────────────────────────────────
# Состояние: state.json
# ─────────────────────────────────────────────────────────────────────────────
def _default_state() -> Dict[str, Any]:
    """Пустое состояние."""
    return {
        "last_run": None,
        "last_result": None,
        "last_checks": None,
        "consecutive_fails": 0,
        "selected_server": None,
        "history": [],
        "node_stats": {},
    }


def load_state() -> Dict[str, Any]:
    """
    Загружает state.json. При отсутствии/повреждении — состояние по
    умолчанию. Битые типы полей восстанавливаются.
    """
    if not os.path.exists(STATE_FILE):
        logger.info("state.json не найден — начинаем с нуля")
        return _default_state()

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Не читается state.json (%s) — сброс", exc)
        return _default_state()

    if not isinstance(data, dict):
        logger.warning("state.json не является объектом — сброс")
        return _default_state()

    default = _default_state()
    for k, v in default.items():
        data.setdefault(k, v)
    if not isinstance(data.get("history"), list):
        data["history"] = []
    if not isinstance(data.get("node_stats"), dict):
        data["node_stats"] = {}
    return data


def save_state(state: Dict[str, Any]) -> None:
    """Атомарная запись state.json (tmp + os.replace)."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    state["last_run"] = datetime.now().isoformat(timespec="seconds")

    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix="state-", suffix=".json", dir=os.path.dirname(STATE_FILE)
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp_path, STATE_FILE)
        logger.info("Состояние сохранено в %s", STATE_FILE)
    except OSError as exc:
        logger.error("Ошибка записи state.json: %s", exc)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def append_history(state: Dict[str, Any], entry: Dict[str, Any]) -> None:
    """Добавляет запись в историю запусков, обрезает по HISTORY_LIMIT."""
    entry.setdefault("timestamp", datetime.now().isoformat(timespec="seconds"))
    hist = state.setdefault("history", [])
    hist.append(entry)
    if len(hist) > HISTORY_LIMIT:
        del hist[:-HISTORY_LIMIT]


# ─────────────────────────────────────────────────────────────────────────────
# Чёрный список узлов
# ─────────────────────────────────────────────────────────────────────────────
def _is_static_blacklisted(address: str) -> bool:
    """Проверка по статическому списку адресов из data.py."""
    return address in SERVER_BLACKLIST_ADDRESSES


def _is_dynamic_blacklisted(address: str, state: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Проверка динамического чёрного списка.
    :return: (в_чёрном_ли, до_какого_времени_ISO или None).
    """
    ns = (state.get("node_stats") or {}).get(address)
    if not ns:
        return False, None
    until_iso = ns.get("blacklisted_until")
    if not until_iso:
        return False, None
    try:
        until_dt = datetime.fromisoformat(until_iso)
    except ValueError:
        return False, None
    if datetime.now() < until_dt:
        return True, until_iso
    return False, None


def is_node_blacklisted(address: str, state: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Комбинированная проверка: статический + динамический чёрный список.
    :return: (запрещён_ли, причина).
    """
    if _is_static_blacklisted(address):
        return True, "static"
    banned, until = _is_dynamic_blacklisted(address, state)
    if banned:
        return True, f"dynamic until {until}"
    return False, None


def update_node_stats(state: Dict[str, Any], servers: Dict[str, Dict[str, Any]]) -> None:
    """
    Обновляет накопительную статистику по узлам. Ключ — `address`
    (ID узлов PassWall2 меняются при обновлении подписки, а адрес стабилен).

    При BLACKLIST_THRESHOLD провалов подряд узел попадает в динамический
    чёрный список на BLACKLIST_DURATION_MIN минут. Первый успех — снимает
    чёрный список.
    """
    now = datetime.now()
    stats = state.setdefault("node_stats", {})

    for srv in servers.values():
        addr = srv["address"]
        ns = stats.setdefault(addr, {
            "node_id": None,
            "remarks": None,
            "consecutive_fails": 0,
            "consecutive_oks": 0,
            "last_seen": None,
            "blacklisted_until": None,
        })

        ns["node_id"] = srv["id"]
        ns["remarks"] = srv["remarks"]
        ns["last_seen"] = now.isoformat(timespec="seconds")

        if srv.get("ok"):
            ns["consecutive_fails"] = 0
            ns["consecutive_oks"] = int(ns.get("consecutive_oks") or 0) + 1
            if ns.get("blacklisted_until"):
                logger.info("Узел %s ('%s') оправился — снимаю чёрный список",
                            addr, srv["remarks"])
            ns["blacklisted_until"] = None
        else:
            ns["consecutive_fails"] = int(ns.get("consecutive_fails") or 0) + 1
            ns["consecutive_oks"] = 0
            if ns["consecutive_fails"] >= BLACKLIST_THRESHOLD:
                until = now + timedelta(minutes=BLACKLIST_DURATION_MIN)
                ns["blacklisted_until"] = until.isoformat(timespec="seconds")
                logger.warning(
                    "Узел %s ('%s') провалил %d проверок подряд — "
                    "в чёрном списке до %s",
                    addr, srv["remarks"], ns["consecutive_fails"],
                    ns["blacklisted_until"],
                )


# ─────────────────────────────────────────────────────────────────────────────
# Сетевые проверки: базовые
# ─────────────────────────────────────────────────────────────────────────────
def tcping(host: str, port: int, timeout: int = TCPING_TIMEOUT) -> Tuple[bool, Optional[float]]:
    """
    TCP-проверка через утилиту `tcping`.

    Синтаксис: tcping -c 1 -t <timeout> -p <port> <host>

    ВАЖНО: при неуспехе возвращаем latency=None — защита от бага, когда
    tcping даже на провале печатает 'time=0.00ms' и нулевая задержка
    попадает в сравнение как лучшая.

    :return: (успех, задержка_мс или None).
    """
    if not host or not port:
        return False, None

    cmd = [
        TCPING_BIN,
        "-c", "1",
        "-t", str(timeout),
        "-p", str(port),
        host,
    ]

    try:
        res = run_command(cmd, timeout=timeout + 3)
    except RuntimeError:
        return False, None

    output = f"{res.stdout or ''}\n{res.stderr or ''}"
    success = res.returncode == 0 or "successful" in output.lower()

    if not success:
        return False, None

    latency: Optional[float] = None
    m = re.search(r"time[=\s]+([\d.]+)\s*ms", output, re.IGNORECASE)
    if not m:
        m = re.search(r"([\d.]+)\s*ms", output)
    if m:
        try:
            latency = float(m.group(1))
        except ValueError:
            latency = None

    if latency is None:
        return False, None
    return True, latency


def curl_https_check(url: str, timeout: int = CURL_TIMEOUT) -> Tuple[bool, Optional[int]]:
    """
    HTTPS GET-проверка через curl.

    Возвращает (получен_ли_ответ, http_code). Если соединение не установлено
    или таймаут — (False, None). Код 0 (curl "000") приводится к None.

    :param url:     URL для проверки;
    :param timeout: таймаут, сек.
    :return:        (got_response, http_code_or_None).
    """
    cmd = [
        CURL_BIN,
        "-s", "-o", "/dev/null",
        "-w", "%{http_code}",
        "--max-time", str(timeout),
        "-L",
        "--insecure",
        url,
    ]
    try:
        res = run_command(cmd, timeout=timeout + 3)
    except RuntimeError:
        return False, None

    code_str = (res.stdout or "").strip()
    try:
        code = int(code_str)
    except ValueError:
        return False, None

    if code == 0:
        return False, None

    return True, code


def url_test(host: str, port: int, timeout: int = TCPING_TIMEOUT) -> Tuple[bool, Optional[float]]:
    """
    «url-test» узла — независимая проверка через чистый Python-сокет.

    Служит второй, независимой от tcping, точкой замера. По ТЗ результат
    url-test имеет приоритет над tcping при выборе latency.

    :return: (успех, задержка_мс или None).
    """
    if not host or not port:
        return False, None

    start = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, (time.monotonic() - start) * 1000.0
    except (OSError, ValueError) as exc:
        logger.debug("url_test %s:%s провалился: %s", host, port, exc)
        return False, None


# ─────────────────────────────────────────────────────────────────────────────
# Внешние проверки: оценка и агрегация
# ─────────────────────────────────────────────────────────────────────────────
def _is_http_code_ok(code: Optional[int]) -> bool:
    """True для 2xx, 301, 302, 307, 308. Всё остальное — не успех."""
    if not code:
        return False
    if 200 <= code < 300:
        return True
    return code in VALID_REDIRECT_CODES


def _is_http_code_5xx(code: Optional[int]) -> bool:
    """True для 5xx."""
    if not code:
        return False
    return 500 <= code < 600


def _format_http_code(code: Optional[int]) -> str:
    """Форматирует HTTP-код для логов. None и 0 → 'timeout'."""
    if code is None or code == 0:
        return "timeout"
    return str(code)


def evaluate_resource(tcp_ok: bool, http_code: Optional[int]) -> Tuple[bool, str]:
    """
    Оценивает доступность одного ресурса по результатам двух проверок.

    Приоритеты:
        1. HTTPS-проверка — главный критерий.
        2. Если HTTP-код валиден (2xx / 301 / 302 / 307 / 308) — ресурс OK.
        3. Если HTTP-код 5xx — приоритет переходит к tcping: tcping OK →
           ресурс OK (сервер лежит, но сеть работает), tcping FAIL → FAIL.
        4. Всё остальное (4xx, 0, timeout) — ресурс НЕ доступен.

    :return: (доступен_ли, краткая_причина).
    """
    if not http_code:
        return False, "https timeout"

    if _is_http_code_ok(http_code):
        return True, f"http {http_code}"

    if _is_http_code_5xx(http_code):
        if tcp_ok:
            return True, f"http {http_code} (fallback to tcping OK)"
        return False, f"http {http_code} (tcping FAIL)"

    return False, f"http {http_code}"


def _check_single_url(url: str) -> Tuple[str, Dict[str, Any]]:
    """
    Проверяет один внешний URL (tcping + curl). Для ThreadPool.

    :return: (url, info). info содержит:
                host, port, tcping_ok, tcping_latency_ms,
                https_ok, http_code, resource_ok, reason.
    """
    host, port = _extract_host_port(url)
    tcp_ok, tcp_lat = tcping(host, port)
    got_response, http_code = curl_https_check(url)

    # https_ok — «HTTP-код валидный», а не «был любой ответ».
    https_ok = got_response and _is_http_code_ok(http_code)

    resource_ok, reason = evaluate_resource(tcp_ok, http_code)

    return url, {
        "host": host,
        "port": port,
        "tcping_ok": tcp_ok,
        "tcping_latency_ms": tcp_lat,
        "https_ok": https_ok,
        "http_code": http_code,
        "resource_ok": resource_ok,
        "reason": reason,
    }


def check_external_resources() -> Tuple[bool, Dict[str, Any]]:
    """
    Шаг 1: параллельная проверка связности с внешними ресурсами.

    Условия успеха:
        * допускается провал НЕ БОЛЕЕ одного ресурса (для N >= 2);
        * для N = 1 — единственный ресурс должен быть доступен.

    Логирование:
        * недоступный ресурс → CRITICAL;
        * общий FAIL → CRITICAL;
        * доступный ресурс → INFO.

    :return: (глобальный_успех, детали по каждому URL).
    """
    total = len(CHECK_URLS)
    logger.info("Проверяю внешние ресурсы (%d шт., параллельно)", total)

    details: Dict[str, Any] = {}
    workers = min(MAX_WORKERS, max(1, total))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_check_single_url, u): u for u in CHECK_URLS}
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                _, info = fut.result()
                details[url] = info
            except Exception as exc:  # noqa: BLE001
                logger.exception("Ошибка проверки ресурса %s: %s", url, exc)
                details[url] = {
                    "resource_ok": False,
                    "reason": f"exception: {exc}",
                }

    # Сводка и подсчёт провалов.
    failed_urls: List[str] = []
    for url in CHECK_URLS:
        info = details.get(url)
        if info is None:
            continue

        if "reason" in info and info["reason"].startswith("exception:"):
            logger.critical("  %s → ERROR: %s", url, info["reason"])
            failed_urls.append(url)
            continue

        level = logging.INFO if info.get("resource_ok") else logging.CRITICAL
        logger.log(
            level,
            "  %s (%s:%s) → tcping=%s(%s), https=%s(%s) → %s [%s]",
            url, info["host"], info["port"],
            "OK" if info["tcping_ok"] else "FAIL",
            _fmt_ms(info["tcping_latency_ms"]),
            "OK" if info["https_ok"] else "FAIL",
            _format_http_code(info["http_code"]),
            "OK" if info["resource_ok"] else "FAIL",
            info["reason"],
        )
        if not info["resource_ok"]:
            failed_urls.append(url)

    # Итоговое решение: не более 1 провала для N >= 2.
    allowed_fails = 1 if total >= 2 else 0
    overall_ok = len(failed_urls) <= allowed_fails

    if overall_ok:
        logger.info(
            "Итог внешних проверок: OK (доступно %d из %d, провалено: %s)",
            total - len(failed_urls), total,
            ", ".join(failed_urls) if failed_urls else "нет",
        )
    else:
        logger.critical(
            "Итог внешних проверок: FAIL (провалено %d из %d: %s)",
            len(failed_urls), total, ", ".join(failed_urls),
        )

    return overall_ok, details


# ─────────────────────────────────────────────────────────────────────────────
# PassWall2: управление
# ─────────────────────────────────────────────────────────────────────────────
def _current_passwall_node_section() -> Optional[str]:
    """ID текущей секции узла PassWall2 из passwall2.@global[0].node."""
    return uci_get(f"{PASSWALL2_GLOBAL}.node")


def restart_passwall2() -> bool:
    """Перезапуск PassWall2 через init-скрипт."""
    if not os.path.exists(PASSWALL2_INIT):
        logger.error("Init-скрипт PassWall2 не найден: %s", PASSWALL2_INIT)
        return False
    logger.info("Перезапускаю PassWall2 (%s restart)", PASSWALL2_INIT)
    try:
        res = run_command([PASSWALL2_INIT, "restart"], timeout=NET_CMD_TIMEOUT)
    except RuntimeError as exc:
        logger.error("Рестарт PassWall2 не выполнен: %s", exc)
        return False
    if res.returncode != 0:
        logger.error("PassWall2 restart вернул код %s", res.returncode)
        return False
    logger.info("Ожидаю %ss после рестарта PassWall2", INIT_RESTART_WAIT)
    time.sleep(INIT_RESTART_WAIT)
    return True


def vpn_switch_to_direct() -> bool:
    """Шаг 2: перевод текущего узла PassWall2 в режим _direct."""
    anchor = _current_passwall_node_section()
    if not anchor:
        logger.error("Не удалось получить anchor PassWall2")
        return False

    logger.info("Отключаю VPN: узел '%s' → '%s'", anchor, DIRECT_NODE)
    if not uci_set(f"{PASSWALL2_PACKAGE}.{anchor}.default_node", DIRECT_NODE):
        return False
    if not uci_commit():
        return False
    return restart_passwall2()


def vpn_update_subscriptions() -> bool:
    """Шаг 3: обновление подписок через Lua-скрипт PassWall2."""
    if not os.path.exists(SUBSCRIBE_LUA):
        logger.error("Скрипт подписок не найден: %s", SUBSCRIBE_LUA)
        return False

    logger.info("Обновляю подписки PassWall2 через %s", SUBSCRIBE_LUA)
    cmd = [LUA_BIN, SUBSCRIBE_LUA, "start", "all", "manual"]
    try:
        res = run_command(cmd, timeout=SUBSCRIBE_WAIT)
    except RuntimeError as exc:
        logger.error("Обновление подписок прервано: %s", exc)
        return False

    if res.returncode != 0:
        logger.error(
            "Обновление подписок завершилось с кодом %s, stderr: %s",
            res.returncode, (res.stderr or "").strip(),
        )
        return False
    logger.info("Подписки успешно обновлены")
    return True


def vpn_set_default_node(node_id: str) -> bool:
    """Шаг 6: установка узла по умолчанию + рестарт."""
    if not node_id:
        logger.error("vpn_set_default_node: пустой node_id")
        return False

    anchor = _current_passwall_node_section()
    if not anchor:
        logger.error("Не удалось получить anchor PassWall2")
        return False

    logger.info("Устанавливаю узел по умолчанию: anchor=%s, node_id=%s",
                anchor, node_id)
    if not uci_set(f"{PASSWALL2_PACKAGE}.{anchor}.default_node", node_id):
        return False
    if not uci_commit():
        return False
    return restart_passwall2()


# ─────────────────────────────────────────────────────────────────────────────
# Парсинг серверов из UCI
# ─────────────────────────────────────────────────────────────────────────────
def _parse_nodes_ids(uci_dump: str) -> List[str]:
    """Из дампа `uci show passwall2` извлекает ID секций-узлов (…=nodes)."""
    ids: List[str] = []
    pattern = re.compile(rf"^{re.escape(PASSWALL2_PACKAGE)}\.([A-Za-z0-9_]+)=nodes\s*$")
    for line in uci_dump.splitlines():
        m = pattern.match(line.strip())
        if m:
            ids.append(m.group(1))
    return ids


def _extract_value_from_dump(uci_dump: str, section_id: str, key: str) -> Optional[str]:
    """Достаёт значение параметра секции из дампа uci show."""
    prefix = f"{PASSWALL2_PACKAGE}.{section_id}.{key}="
    for line in uci_dump.splitlines():
        line = line.strip()
        if not line.startswith(prefix):
            continue
        raw = line[len(prefix):]
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
            raw = raw[1:-1]
        return raw
    return None


def parse_passwall2_nodes() -> Dict[str, Dict[str, Any]]:
    """
    Шаг 4: собирает словарь узлов из UCI-конфигурации.
    Формат:
        {"<id>": {"id","remarks","address","port","latency":None,"ok":None}, ...}
    """
    dump = uci_show(PASSWALL2_PACKAGE)
    if not dump:
        logger.error("Пустой дамп UCI для %s", PASSWALL2_PACKAGE)
        return {}

    ids = _parse_nodes_ids(dump)
    logger.info("Найдено секций-узлов PassWall2: %d", len(ids))

    servers: Dict[str, Dict[str, Any]] = {}
    for sid in ids:
        remarks = _extract_value_from_dump(dump, sid, "remarks") or sid
        address = _extract_value_from_dump(dump, sid, "address")
        port_s  = _extract_value_from_dump(dump, sid, "port")

        if not address:
            logger.warning("Пропускаю узел %s ('%s'): не задан address", sid, remarks)
            continue
        try:
            port = int(port_s) if port_s else None
        except ValueError:
            logger.warning("Пропускаю узел %s ('%s'): некорректный port=%r",
                           sid, remarks, port_s)
            continue
        if port is None:
            logger.warning("Пропускаю узел %s ('%s'): не задан port", sid, remarks)
            continue

        servers[sid] = {
            "id": sid,
            "remarks": remarks,
            "address": address,
            "port": port,
            "latency": None,
            "ok": None,
        }
        logger.info("  Узел: id=%s, remarks='%s', address=%s, port=%s",
                    sid, remarks, address, port)

    logger.info("Итого пригодных узлов: %d", len(servers))
    return servers


# ─────────────────────────────────────────────────────────────────────────────
# Замер задержек (параллельно)
# ─────────────────────────────────────────────────────────────────────────────
def _check_one_server(srv: Dict[str, Any]) -> Dict[str, Any]:
    """
    Проверяет один сервер (tcping + url_test). Возвращает словарь
    с полями latency / latency_source / ok.

    Приоритет latency:
        1. url_test — если он успешен;
        2. tcping   — только если url_test провалился.
    """
    address, port = srv["address"], srv["port"]

    tcp_ok, tcp_lat = tcping(address, port)
    url_ok, url_lat = url_test(address, port)

    if url_ok and url_lat is not None:
        latency, source, ok = url_lat, "url_test", True
    elif tcp_ok and tcp_lat is not None:
        latency, source, ok = tcp_lat, "tcping", True
    else:
        latency, source, ok = None, None, False

    result = dict(srv)
    result.update({
        "tcping_ok": tcp_ok,
        "tcping_latency": tcp_lat,
        "url_ok": url_ok,
        "url_latency": url_lat,
        "latency": latency,
        "latency_source": source,
        "ok": ok,
    })
    return result


def measure_servers_latency(
    servers: Dict[str, Dict[str, Any]],
    max_workers: int = MAX_WORKERS,
) -> Dict[str, Dict[str, Any]]:
    """
    Шаг 5: параллельный замер задержек по всем узлам.
    Общее время ≈ время самого медленного узла.
    """
    if not servers:
        return {}

    logger.info("Замеряю задержки: %d узлов, параллельно (workers=%d)",
                len(servers), max_workers)
    results: Dict[str, Dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_check_one_server, srv): sid
                   for sid, srv in servers.items()}
        for fut in as_completed(futures):
            sid = futures[fut]
            try:
                results[sid] = fut.result()
            except Exception as exc:  # noqa: BLE001
                logger.exception("Ошибка проверки узла %s: %s", sid, exc)
                bad = dict(servers[sid])
                bad.update({"ok": False, "latency": None,
                            "tcping_ok": False, "url_ok": False})
                results[sid] = bad

    for sid, srv in results.items():
        logger.info(
            "  %s ('%s') %s:%s → tcping=%s(%s), url_test=%s(%s) → latency=%s (src=%s)",
            sid, srv["remarks"], srv["address"], srv["port"],
            "OK" if srv.get("tcping_ok") else "FAIL",
            _fmt_ms(srv.get("tcping_latency")),
            "OK" if srv.get("url_ok") else "FAIL",
            _fmt_ms(srv.get("url_latency")),
            _fmt_ms(srv.get("latency")),
            srv.get("latency_source") or "n/a",
        )
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Шаг 6: выбор лучшего сервера
# ─────────────────────────────────────────────────────────────────────────────
def select_best_server(
    servers: Dict[str, Dict[str, Any]],
    state: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    Выбирает узел с минимальной задержкой среди доступных.

    Отсеиваются:
        * провалившие текущий замер (ok=False);
        * попавшие в статический чёрный список;
        * попавшие в динамический чёрный список (state.node_stats).
    """
    available: List[Dict[str, Any]] = []
    skipped: List[Tuple[str, str, str]] = []

    for srv in servers.values():
        if not srv.get("ok") or srv.get("latency") is None:
            continue
        banned, reason = is_node_blacklisted(srv["address"], state)
        if banned:
            skipped.append((srv["id"], srv["address"], reason or ""))
            continue
        available.append(srv)

    for sid, addr, reason in skipped:
        logger.info("Пропускаю узел %s (%s): %s", sid, addr, reason)

    if not available:
        logger.error("Нет доступных узлов после фильтрации")
        return None

    available.sort(key=lambda s: s["latency"])
    best = available[0]
    logger.info(
        "Лучший узел: id=%s, remarks='%s', %s:%s, latency=%s (src=%s)",
        best["id"], best["remarks"], best["address"], best["port"],
        _fmt_ms(best["latency"]), best.get("latency_source") or "n/a",
    )
    return best


# ─────────────────────────────────────────────────────────────────────────────
# Основной сценарий
# ─────────────────────────────────────────────────────────────────────────────
def _log_banner(title: str) -> None:
    """Заметный заголовок в логе."""
    line = "─" * 60
    logger.info(line)
    logger.info(title)
    logger.info(line)


def _finish_with_error(
    state: Dict[str, Any],
    reason: str,
    extra: Optional[Dict[str, Any]] = None,
) -> int:
    """
    Единообразное завершение с ошибкой: пишет состояние и историю, возвращает 1.
    """
    logger.error("Завершаю с ошибкой: %s", reason)
    state["last_result"] = "fail"
    entry = {"result": "fail", "reason": reason}
    if extra:
        entry.update(extra)
    append_history(state, entry)
    save_state(state)
    return 1


def main() -> int:
    """Точка входа. Возвращает код выхода процесса."""
    _log_banner("netwatcher: запуск")
    validate_config()
    logger.info("PID=%s, euid=%s", os.getpid(), os.geteuid())

    for tool in (UCI_BIN, CURL_BIN, LUA_BIN, TCPING_BIN):
        path = which(tool)
        if path:
            logger.info("Утилита '%s' найдена: %s", tool, path)
        else:
            logger.warning("Утилита '%s' не найдена в PATH", tool)

    # ── Загружаем состояние ────────────────────────────────────────────
    state = load_state()
    logger.info(
        "Предыдущее состояние: last_result=%s, consecutive_fails=%s, узлов в статистике=%d",
        state.get("last_result"),
        state.get("consecutive_fails"),
        len(state.get("node_stats") or {}),
    )

    # ── Шаг 1: проверка связности ──────────────────────────────────────
    ok, details = check_external_resources()
    state["last_checks"] = details

    if ok:
        logger.info("Связность в порядке — завершаюсь")
        state["last_result"] = "ok"
        state["consecutive_fails"] = 0
        append_history(state, {"result": "ok", "checks": details})
        save_state(state)
        return 0

    prev_result = state.get("last_result")
    if prev_result != "fail":
        logger.warning(
            "Связности нет, но предыдущий результат '%s' — жду подтверждения",
            prev_result,
        )
        state["last_result"] = "fail"
        state["consecutive_fails"] = int(state.get("consecutive_fails") or 0) + 1
        append_history(state, {"result": "fail",
                               "reason": "first failure in streak",
                               "checks": details})
        save_state(state)
        return 0

    logger.warning("Подтверждённый сбой связи (2 запуска подряд) — начинаю переключение")
    state["consecutive_fails"] = int(state.get("consecutive_fails") or 0) + 1

    # ── Шаг 2: отключение VPN ──────────────────────────────────────────
    if not vpn_switch_to_direct():
        return _finish_with_error(state, "не удалось перевести PassWall2 в _direct")

    # ── Шаг 3: обновление подписок ────────────────────────────────────
    if not vpn_update_subscriptions():
        return _finish_with_error(state, "обновление подписок провалилось")

    # ── Шаг 4: парсинг узлов ──────────────────────────────────────────
    servers = parse_passwall2_nodes()
    if not servers:
        return _finish_with_error(state, "список узлов пуст")

    # ── Шаг 5: замер задержек ─────────────────────────────────────────
    servers = measure_servers_latency(servers)

    # Обновляем статистику ДО выбора, чтобы динамический чёрный список
    # учитывался уже в этом запуске.
    update_node_stats(state, servers)

    # ── Шаг 6: выбор и установка ──────────────────────────────────────
    best = select_best_server(servers, state)
    if not best:
        summary = {
            sid: {
                "remarks": s.get("remarks"),
                "address": s.get("address"),
                "latency": s.get("latency"),
                "ok": s.get("ok"),
            }
            for sid, s in servers.items()
        }
        return _finish_with_error(
            state,
            "ни один узел не прошёл проверку / все в чёрном списке",
            extra={"servers": summary},
        )

    if not vpn_set_default_node(best["id"]):
        return _finish_with_error(
            state,
            f"не удалось установить узел {best['id']} по умолчанию",
        )

    # Успех.
    state["last_result"] = "switched"
    state["selected_server"] = {
        "id": best["id"],
        "remarks": best["remarks"],
        "address": best["address"],
        "port": best["port"],
        "latency": best["latency"],
        "latency_source": best.get("latency_source"),
    }
    summary = {
        sid: {
            "remarks": s.get("remarks"),
            "address": s.get("address"),
            "latency": s.get("latency"),
            "latency_source": s.get("latency_source"),
            "ok": s.get("ok"),
        }
        for sid, s in servers.items()
    }
    append_history(state, {
        "result": "switched",
        "selected": state["selected_server"],
        "servers": summary,
    })
    save_state(state)

    _log_banner(
        f"netwatcher: переключено на {best['id']} ('{best['remarks']}', "
        f"{best['address']}:{best['port']}) задержка={_fmt_ms(best['latency'])}"
    )
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Запуск
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.warning("Прервано пользователем (Ctrl+C)")
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Непредвиденная ошибка: %s", exc)
        sys.exit(1)
