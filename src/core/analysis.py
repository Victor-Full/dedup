"""Análise compartilhada pela interface e pela execução manual."""

from datetime import datetime, timezone
from uuid import UUID, uuid4
from core.cancellation import AnalysisCancelled
from core.scanner import Scanner
from core.hasher import Hasher
from core.report_store import ReportStore
from core.run_lock import exclusive
from utils.audit import OperationAuditError
from utils.logger import audit_event, AuditError
from utils.config_parser import (
    validate_config,
    CONFIG_PATH,
    PROJECT_ROOT,
)


def prepare_config(
    config,
    store,
    extra_exclusions=(),
):
    config = validate_config(config)
    database = str(store.database_path)

    return validate_config({
        **config,
        "excluded_paths": (
            config["excluded_paths"]
            + [
                database + suffix
                for suffix in (
                    "",
                    "-journal",
                    "-wal",
                    "-shm",
                )
            ]
            + [
                str(CONFIG_PATH),
                str(PROJECT_ROOT / "logs"),
                *(
                    str(path)
                    for path in extra_exclusions
                ),
            ]
        ),
    })


@exclusive
def run_analysis(
    config,
    *,
    report_store=None,
    progress=lambda message: None,
    checkpoint=None,
    analysis_id=None,
    extra_exclusions=(),
    check_cancel=None,
):
    analysis_id = (
        str(uuid4())
        if analysis_id is None
        else analysis_id
    )

    if str(UUID(analysis_id)) != analysis_id:
        raise ValueError(
            "Identificador de análise inválido."
        )

    check = check_cancel or (lambda: None)
    check()
    audit_errors = []

    store = (
        ReportStore()
        if report_store is None
        else report_store
    )

    config = prepare_config(
        config,
        store,
        extra_exclusions,
    )

    try:
        audit_event(
            "SCAN_STARTED",
            analysis_id=analysis_id,
        )

        started_at = datetime.now(
            timezone.utc
        ).isoformat()

        progress(
            "Fase 1/3: inventariando arquivos "
            "e registrando falhas..."
        )

        scanner = Scanner(
            config["monitored_paths"],
            ignored_dirs=config["ignored_dirs"],
            ignored_exts=config["ignored_exts"],
            excluded_paths=config["excluded_paths"],
            min_file_size_bytes=config["min_file_size_bytes"],
            ignored_path_patterns=config["ignored_path_patterns"],
            check_cancel=check,
        )

        size_groups = scanner.scan_directory()

        progress(
            "Fase 2/3: prefixo de 64 KiB, SHA-256 completo "
            "e bytes; falhas serão tratadas "
            "na recuperação final..."
        )

        candidates_by_size = {}
        inventory_failures = {}

        def prior_failures_for(groups):
            return {
                record["path"]: inventory_failures[
                    record["path"]
                ]
                for files in groups.values()
                for record in files
                if record["path"] in inventory_failures
            }

        def recover_candidates():
            pending_count = len(
                scanner.pending_errors
            )

            progress(
                f"Fase 3/3: recuperação final; "
                f"{pending_count} locais pendentes "
                "no inventário; somente candidatos "
                "com tentativa restante poderão ser repetidos..."
            )

            groups = (
                scanner.retry_errors()
                if pending_count
                else size_groups
            )

            inventory_failures.update({
                item["path"]: item["attempts"] - 1
                for item in scanner.recovered_errors
                if (
                    item["stage"] == "file"
                    and item["resolution"] == "INVENTORIED"
                )
            })

            for record in scanner.inventory:
                if (
                    record.get("same_file_as") is None
                    and record["size_bytes"]
                    >= config["min_file_size_bytes"]
                ):
                    candidates_by_size.setdefault(
                        record["size_bytes"],
                        [],
                    ).append(record)

            return groups, prior_failures_for(groups)

        def candidates_for_size(size):
            files = candidates_by_size.get(
                size,
                [],
            )
            groups = {size: files} if files else {}

            return groups, prior_failures_for(groups)

        hasher = Hasher(
            chunk_size=config["chunk_size_bytes"],
            check_cancel=check,
        )

        duplicates = hasher.find_duplicates(
            size_groups,
            recover_candidates=recover_candidates,
            candidates_for_size=candidates_for_size,
        )

        report = {
            "duplicates": duplicates,
            "inventory": scanner.inventory,
            "scan_errors": scanner.errors,
            "scan_pending_errors": scanner.pending_errors,
            "scan_recovered_errors": scanner.recovered_errors,
            "scan_summary": scanner.summary,
            "skipped": scanner.skipped,
            "records": hasher.records,
            "comparison_errors": hasher.errors,
            "pending_files": hasher.pending_files,
            "recovered_files": hasher.recovered_files,
            "summary": hasher.summary,
        }

        finished_at = datetime.now(
            timezone.utc
        ).isoformat()

        check()

        if checkpoint is not None:
            checkpoint({
                "analysis_id": analysis_id,
                "report": report,
                "config": config,
                "started_at": started_at,
                "finished_at": finished_at,
            })

        progress(
            "Salvando relatório da análise..."
        )

        attempt_id = analysis_id

        try:
            audit_event(
                "SCAN_COMPLETED",
                analysis_id=analysis_id,
                inventory_files=len(scanner.inventory),
                duplicate_groups=len(duplicates),
                pending_files=len(hasher.pending_files),
                pending_locations=len(scanner.pending_errors),
            )

        except AuditError as audit_error:
            audit_errors.append(
                str(audit_error)
            )

        try:
            report_id = store.save_report(
                report,
                config,
                started_at=started_at,
                finished_at=finished_at,
                report_id=attempt_id,
            )

            persistence = {
                "saved": True,
                "report_id": report_id,
                "error": None,
            }

        except OperationAuditError as error:
            audit_errors.append(str(error))

            persistence = {
                "saved": error.completed,
                "report_id": (
                    error.result
                    if error.completed else None
                ),
                "error": (
                    None
                    if error.completed else str(error)
                ),
            }

        except Exception as error:
            if isinstance(error, AuditError):
                audit_errors.append(
                    str(error)
                )

            persistence = {
                "saved": False,
                "report_id": None,
                "error": (
                    f"{type(error).__name__}: {error}"
                ),
            }

        report["persistence"] = {
            **persistence,
            "started_at": started_at,
            "finished_at": finished_at,
            "attempt_id": attempt_id,
            "config": config,
            "save_attempts": 1,
            "audit_error": (
                " | ".join(audit_errors)
                or None
            ),
        }

        return report

    except Exception as error:
        try:
            audit_event(
                (
                "SCAN_CANCELLED"
                    if isinstance(error, AnalysisCancelled)
                    else "SCAN_FAILED"
                ),
                analysis_id=analysis_id,
                error_type=type(error).__name__,
                error=str(error),
            )

        except AuditError as audit_error:
            error.add_note(
                f"Auditoria: {audit_error}"
            )

        raise