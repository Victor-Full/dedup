"""Regras regex de exclusão, com limites e falha explícita."""

from pathlib import Path

import regex

MAX_PATTERNS = 32
MAX_PATTERN_LENGTH = 512
MATCH_TIMEOUT_SECONDS = 0.02

class ExclusionPatternError(ValueError):
    """Regra inválida ou avaliação que excedeu o limite de tempo."""

class ExclusionPatterns:
    def __init__(self, patterns=None):
        if (
            not isinstance(patterns, (list, tuple))
            or len(patterns) > MAX_PATTERNS
        ):
            raise ExclusionPatternError(
                f"Informe até {MAX_PATTERNS} expressões."
            )

        unique = []

        for expression in patterns:
            if (
                not isinstance(expression, str)
                or not expression.strip()
                or len(expression) > MAX_PATTERN_LENGTH
                or any(ord(char) < 32 for char in expression)
            ):
                raise ExclusionPatternError(
                    "Expressão vazia, excessiva ou com controles."
                )

            if expression not in unique:
                unique.append(expression)

        try:
            self.rules = tuple(
                (
                    text,
                    regex.compile(text, regex.VERSION1),
                )
                for text in unique
            )
        except (regex.error, RecursionError) as error:
            raise ExclusionPatternError(
                f"Expressão de exclusão inválida: {error}"
            ) from error

    def first_match(self, path):
        # Caminho absoluto com barras '/', preservando maiúsculas/minúsculas.
        text = Path(path).as_posix()

        for expression, compiled in self.rules:
            try:
                matched = compiled.search(
                    text,
                    timeout=MATCH_TIMEOUT_SECONDS,
                )
            except TimeoutError as error:
                raise ExclusionPatternError(
                    f"Tempo excedido na regra {expression!r}; "
                    "análise interrompida."
                ) from error

            if matched is not None:
                return expression

        return None