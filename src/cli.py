"""Execução manual por setor. Somente análise; Ctrl+C interrompe."""

import argparse
import json
import sys
from pathlib import Path

from core.analysis import run_analysis
from core.report_store import ReportStore, DATABASE_PATH
from core.run_lock import RunLock, RunBusyError
from core.run_journal import RunJournal, StateError, _json
from utils.config_parser import (
    load_config,
    validate_config,
    ConfigError,
    PROJECT_ROOT,
)
from utils.logger import audit_event, AuditError


STATE_DIR = PROJECT_ROOT / "data" / "execucoes"


def _save_snapshot(snapshot, store):
    config = validate_config(snapshot["config"])
    identifier = snapshot["analysis_id"]

    try:
        store.save_report(
            snapshot["report"],
            config,
            report_id=identifier,
            started_at=snapshot["started_at"],
            finished_at=snapshot["finished_at"],
        )

        return {
            "saved": True,
            "report_id": identifier,
            "error": None,
            "audit_error": None,
        }

    except Exception as error:
        try:
            existing = store.get_report(identifier)

            if (
                existing["report"]
                != json.loads(_json(snapshot["report"]))
                or existing["config"] != config
                or existing["started_at"]
                != snapshot["started_at"]
                or existing["finished_at"]
                != snapshot["finished_at"]
            ):
                raise ValueError(
                    "O UUID pertence a outro relatório."
                )

        except Exception:
            return {
                "saved": False,
                "report_id": None,
                "error": str(error),
                "audit_error": (
                    str(error)
                    if isinstance(error, AuditError)
                    else None
                ),
            }

        return {
            "saved": True,
            "report_id": identifier,
            "error": None,
            "audit_error": (
                str(error)
                if isinstance(error, AuditError)
                else None
            ),
        }


def _finish(journal, report, persistence):
    pending = bool(
        report["pending_files"]
        or report["scan_pending_errors"]
    )

    code = (
        5 if persistence.get("audit_error")
        else 4 if not persistence["saved"]
        else 3 if pending
        else 0
    )

    state = {
        0: "CONCLUDED",
        3: "CONCLUDED_WITH_PENDING",
        4: "REPORT_UNSAVED",
        5: "AUDIT_PENDING",
    }[code]

    journal.update(
        state=state,
        persistence=persistence,
        exit_code=code,
        summary=report["summary"],
        error=persistence.get("error"),
    )

    print(
        f"Estado: {state}; "
        f"relatório: {persistence.get('report_id')}"
    )
    print(
        f"Registro de execução: {journal.path}"
    )

    return code


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Análise manual de duplicatas; "
            "não remove nem move arquivos."
        ),
        allow_abbrev=False,
    )

    group = parser.add_mutually_exclusive_group(
        required=True
    )

    group.add_argument("--perfil", type=Path)
    group.add_argument("--recuperar", type=Path)
    group.add_argument("--estado", type=Path)

    parser.add_argument(
        "--validar",
        action="store_true",
    )
    parser.add_argument("--banco", type=Path)
    parser.add_argument(
        "--diretorio-execucoes",
        type=Path,
        default=STATE_DIR,
    )

    args = parser.parse_args(argv)
    journal = None

    try:
        if args.validar and args.perfil is None:
            raise ConfigError(
                "--validar exige --perfil."
            )

        if args.estado is not None:
            journal = RunJournal.read(
                args.estado
            )

            print(json.dumps(
                {
                    key: value
                    for key, value in journal.data.items()
                    if key not in ("snapshot",)
                },
                indent=2,
                ensure_ascii=True,
            ))

            return 0

        if args.perfil is not None:
            profile = args.perfil.resolve(
                strict=True
            )

            if not profile.is_file():
                raise ConfigError(
                    "O perfil deve ser um arquivo JSON."
                )

            config = load_config(profile)

            if not config["monitored_paths"]:
                raise ConfigError(
                    "O perfil deve informar "
                    "pelo menos uma pasta."
                )

            if args.validar:
                print(json.dumps(
                    config,
                    indent=2,
                    ensure_ascii=True,
                ))
                return 0

            directory = (
                args.diretorio_execucoes.resolve()
            )

            for root in config["monitored_paths"]:
                if Path(root).is_relative_to(directory):
                    raise ConfigError(
                        "A pasta de estados não pode "
                        "conter a pasta analisada."
                    )

            database = (
                args.banco or DATABASE_PATH
            ).resolve()

            with RunLock():
                journal = RunJournal.create(
                    directory,
                    profile=profile,
                    database=database,
                )

                print(
                    f"Execução: {journal.path}",
                    flush=True,
                )

                def progress(message):
                    journal.update(phase=message)
                    print(message, flush=True)

                def checkpoint(snapshot):
                    journal.update(
                        state="REPORT_READY",
                        snapshot=snapshot,
                    )

                report = run_analysis(
                    config,
                    report_store=ReportStore(database),
                    progress=progress,
                    checkpoint=checkpoint,
                    analysis_id=journal.data["run_id"],
                    extra_exclusions=(
                        profile,
                        directory,
                    ),
                )

                return _finish(
                    journal,
                    report,
                    report["persistence"],
                )

        with RunLock():
            journal = RunJournal.read(
                args.recuperar
            )

            snapshot = journal.data.get(
                "snapshot"
            )

            if not isinstance(snapshot, dict):
                raise StateError(
                    "Não há relatório completo para recuperar. "
                    "Execute o perfil novamente."
                )

            database = (
                args.banco
                or Path(journal.data["database"])
            ).resolve()

            audit_event(
                "MANUAL_REPORT_RECOVERY",
                run_id=journal.data["run_id"],
            )

            persistence = _save_snapshot(
                snapshot,
                ReportStore(database),
            )

            return _finish(
                journal,
                snapshot["report"],
                persistence,
            )

    except KeyboardInterrupt:
        code = 130
        state = "INTERRUPTED"
        error = "Interrompido pelo operador."

    except RunBusyError as failure:
        code, state, error = (
            6,
            "BUSY",
            str(failure),
        )

    except AuditError as failure:
        code, state, error = (
            5,
            "AUDIT_PENDING",
            str(failure),
        )

    except (
        ConfigError,
        FileNotFoundError,
        ValueError,
    ) as failure:
        code, state, error = (
            2,
            "INVALID_CONFIGURATION",
            str(failure),
        )

    except (
        StateError,
        OSError,
    ) as failure:
        code, state, error = (
            7,
            "STORAGE_ERROR",
            str(failure),
        )

    except Exception as failure:
        code, state, error = (
            8,
            "FAILED",
            str(failure),
        )

    if journal is not None:
        # Uma substituição do arquivo pode ter terminado
        # antes de a interrupção chegar ao Python.
        try:
            journal = RunJournal.read(
                journal.path
            )

        except StateError as failure:
            print(
                f"Estado preservado para inspeção: {failure}",
                file=sys.stderr,
            )
            print(
                f"{state}: {error}",
                file=sys.stderr,
            )
            return code

        try:
            audit_event(
                "MANUAL_RUN_STOPPED",
                run_id=journal.data["run_id"],
                state=state,
                error=error,
                exit_code=code,
            )

        except AuditError as failure:
            print(
                f"Auditoria indisponível: {failure}",
                file=sys.stderr,
            )

        try:
            journal.update(
                state=state,
                error=error,
                exit_code=code,
            )

        except Exception as failure:
            print(
                "Não foi possível atualizar "
                f"o estado: {failure}",
                file=sys.stderr,
            )

    print(
        f"{state}: {error}",
        file=sys.stderr,
    )

    return code


if __name__ == "__main__":
    sys.exit(main())