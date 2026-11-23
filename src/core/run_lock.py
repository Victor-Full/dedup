"""Exclusão mútua entre processos no mesmo Windows."""

import ctypes
import os
from ctypes import wintypes
from functools import wraps


LOCK_NAME = r"Global\Dedup_Manual_Operation_v1"


class RunBusyError(RuntimeError):
    pass


class RunLock:
    def __init__(self, name=LOCK_NAME):
        self.name = name
        self.handle = None
        self.abandoned = False

    def __enter__(self):
        if os.name != "nt":
            raise OSError("Esta versão exige Windows.")

        api = ctypes.WinDLL(
            "kernel32",
            use_last_error=True,
        )

        api.CreateMutexW.argtypes = (
            wintypes.LPVOID,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        )
        api.CreateMutexW.restype = wintypes.HANDLE

        api.WaitForSingleObject.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
        )
        api.WaitForSingleObject.restype = wintypes.DWORD

        api.ReleaseMutex.argtypes = (
            wintypes.HANDLE,
        )
        api.ReleaseMutex.restype = wintypes.BOOL

        api.CloseHandle.argtypes = (
            wintypes.HANDLE,
        )
        api.CloseHandle.restype = wintypes.BOOL

        handle = api.CreateMutexW(
            None,
            False,
            self.name,
        )

        if not handle:
            raise ctypes.WinError(
                ctypes.get_last_error()
            )

        result = api.WaitForSingleObject(handle, 0)

        if result not in (0, 0x80):
            error = ctypes.get_last_error()
            api.CloseHandle(handle)

            if result == 0x102:
                raise RunBusyError(
                    "Outra operação do Dedup está em execução."
                )

            raise ctypes.WinError(error)

        self.api = api
        self.handle = handle
        self.abandoned = result == 0x80

        return self

    def __exit__(self, exc_type, exc, traceback):
        try:
            if not self.api.ReleaseMutex(self.handle):
                raise ctypes.WinError(
                    ctypes.get_last_error()
                )
        finally:
            self.api.CloseHandle(self.handle)
            self.handle = None


def exclusive(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with RunLock():
            return function(*args, **kwargs)

    return wrapped