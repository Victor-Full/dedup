"""Cancelamento cooperativo; nunca encerra uma thread à força."""

from threading import Event


class AnalysisCancelled(Exception):
    pass


class Cancellation:
    def __init__(self):
        self._requested = Event()

    def request(self):
        self._requested.set()

    def requested(self):
        return self._requested.is_set()

    def check(self):
        if self._requested.is_set():
            raise AnalysisCancelled(
                "Análise cancelada pelo usuário."
            )