"""Estado de execução e checkpoint de relatório."""

import hashlib
import json
import os
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4


MAX_STATE_BYTES = 256 * 1024 * 1024


class StateError(OSError):
    pass


def _unsupported(value):
    raise TypeError(
        f"Tipo não permitido no estado: "
        f"{type(value).__name__}"
    )


def _json(value):
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        default=lambda item: (
            str(item)
            if isinstance(item, Path)
            else _unsupported(item)
        ),
    ).encode("utf-8")


def _object(pairs):
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(
                f"Campo repetido: {key}"
            )

        result[key] = value

    return result


def _constant(value):
    raise ValueError(
        f"Constante JSON inválida: {value}"
    )


class RunJournal:
    def __init__(self, path, data):
        self.path = Path(path)
        self.data = data

    @classmethod
    def create(
        cls,
        directory,
        *,
        profile,
        database,
    ):
        identifier = str(uuid4())

        journal = cls(
            Path(directory) / f"{identifier}.json",
            {
                "run_id": identifier,
                "profile": str(profile),
                "database": str(database),
                "host": socket.gethostname(),
                "pid": os.getpid(),
                "created_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            },
        )

        journal.update(state="RUNNING")
        return journal

    @classmethod
    def read(cls, path):
        try:
            path = Path(path).resolve(
                strict=True
            )

            with path.open("rb") as stream:
                raw = stream.read(
                    MAX_STATE_BYTES + 1
                )

            if len(raw) > MAX_STATE_BYTES:
                raise ValueError(
                    "Estado excede 256 MiB."
                )

            envelope = json.loads(
                raw,
                object_pairs_hook=_object,
                parse_constant=_constant,
            )

            data = envelope["payload"]

            if (
                type(
                    envelope.get("format_version")
                ) is not int
                or envelope["format_version"] != 1
                or not isinstance(data, dict)
                or hashlib.sha256(
                    _json(data)
                ).hexdigest() != envelope["sha256"]
                or str(UUID(data["run_id"]))
                != data["run_id"]
                or path.name
                != data["run_id"] + ".json"
            ):
                raise ValueError(
                    "Estrutura, nome ou checksum inválido."
                )

            return cls(path, data)

        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            RecursionError,
        ) as error:
            raise StateError(
                f"Estado inválido ou inacessível: {error}"
            ) from error

    def update(self, **changes):
        temporary = None

        try:
            data = {
                **self.data,
                **changes,
                "updated_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            }

            encoded = _json(data)

            raw = _json({
                "format_version": 1,
                "payload": json.loads(encoded),
                "sha256": hashlib.sha256(
                    encoded
                ).hexdigest(),
            })

            if len(raw) > MAX_STATE_BYTES:
                raise ValueError(
                    "Estado excede 256 MiB; reduza o lote."
                )

            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self.path.parent,
                suffix=".tmp",
                delete=False,
            ) as stream:
                temporary = Path(stream.name)

                if stream.write(raw) != len(raw):
                    raise OSError(
                        "Gravação incompleta do estado."
                    )

                stream.flush()
                os.fsync(stream.fileno())

            os.replace(
                temporary,
                self.path,
            )

            # Guarda uma cópia independente dos objetos
            # que continuam sendo usados pela análise.
            self.data = json.loads(encoded)

        except (
            OSError,
            ValueError,
            TypeError,
            RecursionError,
        ) as error:
            raise StateError(
                f"Não foi possível gravar o estado: {error}"
            ) from error

        finally:
            if temporary is not None:
                temporary.unlink(
                    missing_ok=True
                )