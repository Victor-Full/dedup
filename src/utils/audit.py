"""Associa início e resultado sem confundir cópia e auditoria."""

import inspect
from functools import wraps
from pathlib import Path
from uuid import uuid4

from utils.logger import AuditError, audit_event


class OperationAuditError(AuditError):
    def __init__(
        self,
        message,
        *,
        completed,
        result=None,
        operation_error=None,
    ):
        super().__init__(message)

        self.completed = completed
        self.result = result
        self.operation_error = operation_error

        self.operation_dir = getattr(
            operation_error,
            "operation_dir",
            None,
        )
        self.partial_path = getattr(
            operation_error,
            "partial_path",
            None,
        )

        if completed and isinstance(result, Path):
            self.partial_path = result
            self.operation_dir = result.parent


def audited_operation(name):
    def decorate(function):
        signature = inspect.signature(function)

        @wraps(function)
        def wrapped(*args, **kwargs):
            arguments = signature.bind(
                *args,
                **kwargs,
            ).arguments

            operation_id = str(uuid4())

            details = {
                "operation_id": operation_id,
            }

            for key in (
                "file_path",
                "backup_path",
                "destination",
                "report_id",
            ):
                if arguments.get(key) is not None:
                    details[key] = str(arguments[key])

            analysis_id = (
                getattr(args[0], "analysis_id", None)
                if args else None
            )

            if analysis_id is not None:
                details["analysis_id"] = str(analysis_id)

            elif arguments.get("report_id") is not None:
                details["analysis_id"] = str(
                    arguments["report_id"]
                )

            # Se este registro falhar, a operação não começa.
            audit_event(
                name + "_STARTED",
                **details,
            )

            try:
                result = function(*args, **kwargs)

            except Exception as error:
                failure = dict(
                    details,
                    error_type=type(error).__name__,
                    error=str(error),
                    operation_dir=str(
                        getattr(error, "operation_dir", None)
                    ),
                    partial_path=str(
                        getattr(error, "partial_path", None)
                    ),
                )

                try:
                    audit_event(
                        name + "_FAILED",
                        **failure,
                    )

                except AuditError as audit_error:
                    raise OperationAuditError(
                        f"Operação falhou: {error}. "
                        f"Auditoria também falhou: {audit_error}",
                        completed=False,
                        operation_error=error,
                    ) from error

                raise

            try:
                audit_event(
                    name + "_SUCCEEDED",
                    **details,
                    result_path_or_id=str(result),
                )

            except AuditError as error:
                raise OperationAuditError(
                    "Operação concluída, mas seu registro "
                    f"final falhou: {error}",
                    completed=True,
                    result=result,
                ) from error

            return result

        return wrapped

    return decorate