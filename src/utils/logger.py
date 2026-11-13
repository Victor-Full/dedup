"""Auditoria JSONL, rotação e falhas de gravação explícitas."""

import getpass
import json
import logging
import os
import socket
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import RLock
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SESSION_ID = str(uuid4())
DEFAULT_LOG_PATH = (
    PROJECT_ROOT / "logs" / f"auditoria_{_SESSION_ID}.jsonl"
)
_SETUP_LOCK = RLock()


class AuditError(OSError):
    pass


def _account():
    # No Windows, os.getlogin consulta GetUserNameW.
    # Não usa USERNAME para atribuir a operação.
    if os.name == "nt":
        return os.getlogin()
    return getpass.getuser()


class AuditFormatter(logging.Formatter):
    def format(self, record):
        event = getattr(
            record,
            "audit_event",
            "APPLICATION_MESSAGE",
        )

        data = {
            "format_version": 1,
            "event_id": str(uuid4()),
            "session_id": _SESSION_ID,
            "occurred_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "account": _account(),
            "host": socket.gethostname(),
            "process_id": os.getpid(),
            "level": record.levelname,
            "event": event,
            "details": getattr(
                record,
                "audit_details",
                {},
            ),
        }

        if event == "APPLICATION_MESSAGE":
            data["message"] = record.getMessage()

            if record.exc_info:
                data["exception"] = self.formatException(
                    record.exc_info
                )

        return json.dumps(
            data,
            ensure_ascii=True,
            allow_nan=False,
        )


class StrictAuditHandler(RotatingFileHandler):
    def emit(self, record):
        try:
            raw = self.format(record)

            if self.shouldRollover(record):
                self.doRollover()

            if self.stream is None:
                self.stream = self._open()

            line = raw + self.terminator

            if self.stream.write(line) != len(line):
                raise OSError(
                    "Gravação incompleta do evento de auditoria."
                )

            self.stream.flush()
            os.fsync(self.stream.fileno())

        except Exception as error:
            raise AuditError(
                f"Falha ao gravar a auditoria em "
                f"{self.baseFilename}: {error}"
            ) from error

    def doRollover(self):
        if self.stream is not None:
            self.stream.close()
            self.stream = None

        stamp = datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%S%fZ"
        )

        archive = (
            self.baseFilename
            + f".{stamp}.{uuid4().hex}.archive"
        )

        # Não elimina arquivos antigos automaticamente.
        os.rename(self.baseFilename, archive)
        self.stream = self._open()


def setup_logger(
    log_file=None,
    *,
    max_bytes=10 * 1024 * 1024,
):
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError(
            "max_bytes deve ser inteiro positivo."
        )

    path = Path(
        DEFAULT_LOG_PATH
        if log_file is None else log_file
    )

    if not path.is_absolute():
        path = PROJECT_ROOT / path

    path = path.resolve()

    with _SETUP_LOCK:
        logger = logging.getLogger("dedup_audit")

        if logger.handlers:
            if (
                len(logger.handlers) != 1
                or not isinstance(
                    logger.handlers[0],
                    StrictAuditHandler,
                )
                or Path(
                    logger.handlers[0].baseFilename
                ) != path
                or logger.handlers[0].maxBytes != max_bytes
            ):
                raise AuditError(
                    "Auditoria já configurada com outro "
                    "destino ou política. Reinicie a aplicação."
                )

            return logger

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        handler = StrictAuditHandler(
            path,
            maxBytes=max_bytes,
            backupCount=1,
            encoding="utf-8",
            delay=False,
        )
        handler.setFormatter(AuditFormatter())

        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False

        return logger


def audit_event(event, **details):
    if not isinstance(event, str) or not event:
        raise ValueError(
            "Evento de auditoria inválido."
        )

    with _SETUP_LOCK:
        logger = logging.getLogger("dedup_audit")

        if not logger.handlers:
            logger = setup_logger()

        if (
            len(logger.handlers) != 1
            or not isinstance(
                logger.handlers[0],
                StrictAuditHandler,
            )
        ):
            raise AuditError(
                "Auditoria sem um gravador obrigatório válido."
            )

        handler = logger.handlers[0]

        record = logging.LogRecord(
            logger.name,
            logging.INFO,
            "",
            0,
            "",
            (),
            None,
        )
        record.audit_event = event
        record.audit_details = details

        # Evita descarte silencioso por nível/filtros do logger.
        handler.acquire()

        try:
            handler.emit(record)
        finally:
            handler.release()