"""Planeja marcações sobre o relatório observado; não acessa o disco."""

import os
from dataclasses import dataclass
from pathlib import Path


class SelectionError(ValueError):
    pass


@dataclass(frozen=True)
class SelectionDecision:
    reference: Path | None
    marked: tuple[Path, ...]
    reason: str


STRATEGIES = {
    "creation_newest": ("creation_time_ns", max),
    "creation_oldest": ("creation_time_ns", min),
    "modified_newest": ("modified_time_ns", max),
    "modified_oldest": ("modified_time_ns", min),
    "official": None,
}

REASONS = {
    "SELECTED": "Referência definida para revisão",
    "INVALID_GROUP": "Grupo inválido ou com menos de dois arquivos",
    "INVALID_PATH": "Caminho inválido no grupo",
    "OUT_OF_SCOPE": "Arquivo fora das pastas da análise",
    "INVALID_EVIDENCE": "Evidência de conteúdo ou versão inválida",
    "SAME_PHYSICAL_FILE": "Há caminhos do mesmo arquivo físico",
    "MISSING_DATE": "Data ausente ou inválida",
    "DATE_TIE": "Empate na data da referência",
    "NO_OFFICIAL_REFERENCE": "Nenhuma cópia na pasta oficial",
    "OFFICIAL_TIE": "Mais de uma cópia na pasta oficial",
}


def _absolute(value):
    try:
        raw = os.fspath(value)
    except TypeError as error:
        raise SelectionError(
            "Informe um caminho absoluto."
        ) from error

    if (
        not isinstance(raw, str)
        or not raw.strip()
        or any(ord(character) < 32 for character in raw)
    ):
        raise SelectionError(
            "Caminho vazio ou com caracteres de controle."
        )

    path = Path(raw)

    if (
        not path.is_absolute()
        or ".." in path.parts
        or (
            os.name == "nt"
            and (
                raw.startswith(("\\\\?\\", "\\\\.\\"))
                or os.path.isreserved(raw)
                or any(
                    ":" in part or part.endswith((" ", "."))
                    for part in path.parts[1:]
                )
            )
        )
    ):
        raise SelectionError(
            "Caminho incompleto, reservado ou ambíguo."
        )

    return Path(os.path.normpath(raw))


def _key(path):
    return os.path.normcase(str(path))


def _within(path, roots):
    return any(
        path.is_relative_to(root)
        for root in roots
    )


def _evidence(record):
    signature = record.get("read_signature")
    identity = record.get("file_id")
    digest = record.get("hash")

    return (
        record.get("analysis_status") == "MATCH_OBSERVED"
        and record.get("same_file_as") is None
        and isinstance(digest, str)
        and len(digest) == 64
        and all(
            character in "0123456789abcdef"
            for character in digest
        )
        and isinstance(signature, (tuple, list))
        and len(signature) == 5
        and all(
            type(value) is int
            for value in signature[:4]
        )
        and (
            signature[4] is None
            or type(signature[4]) is int
        )
        and signature[1] > 0
        and signature[2] >= 0
        and type(record.get("size_bytes")) is int
        and type(record.get("modified_time_ns")) is int
        and signature[2] == record["size_bytes"]
        and signature[3] == record["modified_time_ns"]
        and isinstance(identity, (tuple, list))
        and len(identity) == 2
        and all(
            type(value) is int
            for value in identity
        )
        and tuple(identity) == tuple(signature[:2])
    )


def plan_selection(
    groups,
    *,
    strategy,
    scope,
    official_directory=None,
):
    if (
        not isinstance(strategy, str)
        or strategy not in STRATEGIES
    ):
        raise SelectionError(
            "Estratégia de seleção desconhecida."
        )

    if not isinstance(groups, (list, tuple)):
        raise SelectionError(
            "Os grupos devem ser uma lista."
        )

    if (
        not isinstance(scope, (list, tuple))
        or not scope
    ):
        raise SelectionError(
            "O escopo da análise não está disponível."
        )

    roots = tuple(
        _absolute(path)
        for path in scope
    )

    official = None

    if strategy == "official":
        official = _absolute(official_directory)

        if not _within(official, roots):
            raise SelectionError(
                "A pasta oficial deve pertencer "
                "ao escopo da análise."
            )

    decisions = []
    seen_paths = set()
    seen_identities = set()

    for group in groups:
        reason = None

        if (
            not isinstance(group, (list, tuple))
            or len(group) < 2
            or not all(
                isinstance(record, dict)
                for record in group
            )
        ):
            decisions.append(
                SelectionDecision(
                    None,
                    (),
                    "INVALID_GROUP",
                )
            )
            continue

        try:
            paths = tuple(
                _absolute(record.get("path"))
                for record in group
            )

        except SelectionError:
            decisions.append(
                SelectionDecision(
                    None,
                    (),
                    "INVALID_PATH",
                )
            )
            continue

        for path in paths:
            key = _key(path)

            if key in seen_paths:
                raise SelectionError(
                    "Um caminho aparece mais de uma vez "
                    "nos grupos."
                )

            seen_paths.add(key)

        if not all(
            _within(path, roots)
            for path in paths
        ):
            reason = "OUT_OF_SCOPE"

        elif (
            not all(
                _evidence(record)
                for record in group
            )
            or len({
                record["hash"]
                for record in group
            }) != 1
            or len({
                record["size_bytes"]
                for record in group
            }) != 1
        ):
            reason = "INVALID_EVIDENCE"

        if reason is not None:
            decisions.append(
                SelectionDecision(None, (), reason)
            )
            continue

        identities = [
            tuple(record["file_id"])
            for record in group
        ]

        if len(set(identities)) != len(identities):
            decisions.append(
                SelectionDecision(
                    None,
                    (),
                    "SAME_PHYSICAL_FILE",
                )
            )
            continue

        if seen_identities.intersection(identities):
            raise SelectionError(
                "Grupos diferentes compartilham "
                "uma identidade de arquivo."
            )

        seen_identities.update(identities)

        if strategy == "official":
            candidates = [
                path
                for path in paths
                if (
                    path != official
                    and path.is_relative_to(official)
                )
            ]

            if not candidates:
                reason = "NO_OFFICIAL_REFERENCE"

            elif len(candidates) != 1:
                reason = "OFFICIAL_TIE"

        else:
            field, choose = STRATEGIES[strategy]

            dates = [
                record.get(field)
                for record in group
            ]

            if not all(
                type(value) is int
                for value in dates
            ):
                reason = "MISSING_DATE"
                candidates = []

            else:
                chosen = choose(dates)

                candidates = [
                    path
                    for path, date in zip(paths, dates)
                    if date == chosen
                ]

                if len(candidates) != 1:
                    reason = "DATE_TIE"

        if reason is not None:
            decisions.append(
                SelectionDecision(None, (), reason)
            )

        else:
            reference = candidates[0]

            decisions.append(
                SelectionDecision(
                    reference,
                    tuple(
                        path
                        for path in paths
                        if path != reference
                    ),
                    "SELECTED",
                )
            )

    return tuple(decisions)