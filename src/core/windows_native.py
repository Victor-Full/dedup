"""APIs Windows usadas exclusivamente pelo fluxo de recuperação."""

import ctypes as C
import os
import struct
from contextlib import contextmanager
from ctypes import wintypes as W

from core.action_manager import BackupError
from core.windows_backup import BasicInfo


P = C.c_void_p


class SecurityAttributes(C.Structure):
    _fields_ = [
        ("length", W.DWORD),
        ("descriptor", P),
        ("inherit", W.BOOL),
    ]


class Luid(C.Structure):
    _fields_ = [
        ("low", W.DWORD),
        ("high", W.LONG),
    ]


class TokenPrivileges(C.Structure):
    _fields_ = [
        ("count", W.DWORD),
        ("luid", Luid),
        ("attributes", W.DWORD),
    ]


def bind(lib, name, result, *arguments):
    function = getattr(lib, name)
    function.restype = result
    function.argtypes = arguments
    return function


class NativeRecovery:
    target_access = 0xC10F0000

    def __init__(self):
        if os.name != "nt":
            raise BackupError(
                "A recuperação completa exige Windows."
            )

        self.k = C.WinDLL(
            "kernel32",
            use_last_error=True,
        )
        self.a = C.WinDLL(
            "advapi32",
            use_last_error=True,
        )

        bind(self.k, "CloseHandle", W.BOOL, W.HANDLE)
        bind(self.k, "CreateDirectoryW", W.BOOL, W.LPCWSTR, P)
        bind(self.k, "GetCurrentProcess", W.HANDLE)
        bind(self.k, "GetCurrentThread", W.HANDLE)
        bind(self.k, "LocalFree", P, P)

        bind(
            self.a, "OpenProcessToken",
            W.BOOL, W.HANDLE, W.DWORD, C.POINTER(P),
        )
        bind(
            self.a, "OpenThreadToken",
            W.BOOL, W.HANDLE, W.DWORD, W.BOOL, C.POINTER(P),
        )
        bind(self.a, "ImpersonateSelf", W.BOOL, C.c_int)
        bind(self.a, "RevertToSelf", W.BOOL)

        bind(
            self.a, "LookupPrivilegeValueW",
            W.BOOL, W.LPCWSTR, W.LPCWSTR, C.POINTER(Luid),
        )
        bind(
            self.a, "AdjustTokenPrivileges",
            W.BOOL, P, W.BOOL, P, W.DWORD, P, P,
        )
        bind(
            self.a, "GetTokenInformation",
            W.BOOL, P, C.c_int, P, W.DWORD,
            C.POINTER(W.DWORD),
        )
        bind(
            self.a, "ConvertSidToStringSidW",
            W.BOOL, P, C.POINTER(P),
        )
        bind(
            self.a,
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            W.BOOL, W.LPCWSTR, W.DWORD, C.POINTER(P), P,
        )
        bind(
            self.a,
            "ConvertSecurityDescriptorToStringSecurityDescriptorW",
            W.BOOL, P, W.DWORD, W.DWORD, C.POINTER(P), P,
        )
        bind(
            self.a, "IsValidSecurityDescriptor",
            W.BOOL, P,
        )
        bind(
            self.a, "GetSecurityDescriptorOwner",
            W.BOOL, P, C.POINTER(P), C.POINTER(W.BOOL),
        )
        bind(
            self.a, "GetSecurityDescriptorDacl",
            W.BOOL, P, C.POINTER(W.BOOL),
            C.POINTER(P), C.POINTER(W.BOOL),
        )
        bind(
            self.a, "SetSecurityInfo",
            W.DWORD, W.HANDLE, C.c_int, W.DWORD,
            P, P, P, P,
        )
        bind(
            self.a, "GetSecurityInfo",
            W.DWORD, W.HANDLE, C.c_int, W.DWORD,
            P, P, P, P, C.POINTER(P),
        )
        bind(
            self.k, "SetFileInformationByHandle",
            W.BOOL, W.HANDLE, C.c_int, P, W.DWORD,
        )
        bind(
            self.k, "FlushFileBuffers",
            W.BOOL, W.HANDLE,
        )
        bind(
            self.k, "BackupWrite",
            W.BOOL, W.HANDLE, P, W.DWORD,
            C.POINTER(W.DWORD), W.BOOL,
            W.BOOL, C.POINTER(P),
        )

    @staticmethod
    def check(success):
        if not success:
            raise C.WinError(
                C.get_last_error()
            )

    @contextmanager
    def privileges(self):
        # Trabalha somente com uma cópia do token nesta thread.
        # Não concede direitos nem altera o token global.
        token = P()

        if self.a.OpenThreadToken(
            self.k.GetCurrentThread(),
            8,
            True,
            C.byref(token),
        ):
            self.k.CloseHandle(token)
            raise BackupError(
                "Contexto de impersonação preexistente não suportado."
            )

        if C.get_last_error() != 1008:
            raise C.WinError(
                C.get_last_error()
            )

        self.check(
            self.a.ImpersonateSelf(2)
        )

        try:
            self.check(self.a.OpenThreadToken(
                self.k.GetCurrentThread(),
                0x28,
                True,
                C.byref(token),
            ))

            for name in (
                "SeBackupPrivilege",
                "SeRestorePrivilege",
                "SeSecurityPrivilege",
            ):
                value = TokenPrivileges()
                value.count = 1
                value.attributes = 2

                self.check(
                    self.a.LookupPrivilegeValueW(
                        None,
                        name,
                        C.byref(value.luid),
                    )
                )

                C.set_last_error(0)

                self.check(
                    self.a.AdjustTokenPrivileges(
                        token,
                        False,
                        C.byref(value),
                        0,
                        None,
                        None,
                    )
                )

                if C.get_last_error() == 1300:
                    raise BackupError(
                        "A conta não possui o direito necessário: "
                        f"{name}."
                    )

            yield

        finally:
            if token.value:
                self.k.CloseHandle(token)

            self.check(
                self.a.RevertToSelf()
            )

    def user_sid(self):
        token = P()

        self.check(self.a.OpenProcessToken(
            self.k.GetCurrentProcess(),
            8,
            C.byref(token),
        ))

        try:
            count = W.DWORD()

            self.a.GetTokenInformation(
                token,
                1,
                None,
                0,
                C.byref(count),
            )

            if not count.value or count.value > 65536:
                raise BackupError(
                    "Não foi possível obter a identidade da conta."
                )

            buffer = C.create_string_buffer(
                count.value
            )

            self.check(self.a.GetTokenInformation(
                token,
                1,
                buffer,
                count,
                C.byref(count),
            ))

            sid = C.cast(
                buffer,
                C.POINTER(P),
            )[0]

            text = P()

            self.check(
                self.a.ConvertSidToStringSidW(
                    sid,
                    C.byref(text),
                )
            )

            try:
                return C.wstring_at(text)
            finally:
                self.k.LocalFree(text)

        finally:
            self.k.CloseHandle(token)

    @contextmanager
    def private_descriptor(self, *, inherit=True):
        sid = self.user_sid()
        flags = "OICI" if inherit else ""

        text = (
            f"O:{sid}D:P"
            f"(A;{flags};FA;;;{sid})"
            f"(A;{flags};FA;;;SY)"
            f"(A;{flags};FA;;;BA)"
        )

        descriptor = P()

        self.check(
            self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text,
                1,
                C.byref(descriptor),
                None,
            )
        )

        try:
            yield descriptor
        finally:
            self.k.LocalFree(descriptor)

    def secure(self, handle, *, directory=False):
        with self.private_descriptor(
            inherit=directory
        ) as descriptor:
            owner = P()
            dacl = P()
            defaulted = W.BOOL()
            present = W.BOOL()

            self.check(
                self.a.GetSecurityDescriptorOwner(
                    descriptor,
                    C.byref(owner),
                    C.byref(defaulted),
                )
            )

            self.check(
                self.a.GetSecurityDescriptorDacl(
                    descriptor,
                    C.byref(present),
                    C.byref(dacl),
                    C.byref(defaulted),
                )
            )

            if (
                not present.value
                or not dacl.value
                or not owner.value
            ):
                raise BackupError(
                    "Descritor privado inválido."
                )

            result = self.a.SetSecurityInfo(
                handle,
                1,
                0x80000005,
                owner,
                None,
                dacl,
                None,
            )

            if result:
                raise C.WinError(result)

            # Confere o resultado efetivamente armazenado.
            observed = P()

            result = self.a.GetSecurityInfo(
                handle,
                1,
                5,
                None,
                None,
                None,
                None,
                C.byref(observed),
            )

            if result:
                raise C.WinError(result)

            try:
                expected_text = self.descriptor_text(
                    descriptor,
                    5,
                )
                observed_text = self.descriptor_text(
                    observed,
                    5,
                )

                expected_owner, expected_acl = (
                    expected_text.split("D:", 1)
                )
                observed_owner, observed_acl = (
                    observed_text.split("D:", 1)
                )

                position = observed_acl.find("(")

                if (
                    position < 0
                    or "P" not in observed_acl[:position]
                    or expected_owner != observed_owner
                    or expected_acl[
                        expected_acl.find("("):
                    ] != observed_acl[position:]
                ):
                    raise BackupError(
                        "O armazenamento não confirmou "
                        "a proteção privada."
                    )

            finally:
                self.k.LocalFree(observed)

    def descriptor_text(
        self,
        descriptor,
        information=15,
    ):
        text = P()

        self.check(
            self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                1,
                information,
                C.byref(text),
                None,
            )
        )

        try:
            return C.wstring_at(text)
        finally:
            self.k.LocalFree(text)

    def security_text(self, data):
        if len(data) < 20:
            raise BackupError(
                "Descritor de segurança truncado."
            )

        (
            revision,
            _,
            control,
            owner,
            group,
            sacl,
            dacl,
        ) = struct.unpack_from(
            "<BBHIIII",
            data,
        )

        if revision != 1 or not control & 0x8000:
            raise BackupError(
                "Descritor relativo de segurança inválido."
            )

        for offset, is_acl in (
            (owner, False),
            (group, False),
            (sacl, True),
            (dacl, True),
        ):
            if not offset:
                continue

            if (
                offset < 20
                or offset % 4
                or offset + 8 > len(data)
            ):
                raise BackupError(
                    "Deslocamento de segurança inválido."
                )

            size = (
                struct.unpack_from(
                    "<H",
                    data,
                    offset + 2,
                )[0]
                if is_acl
                else 8 + 4 * data[offset + 1]
            )

            if size < 8 or offset + size > len(data):
                raise BackupError(
                    "Componente de segurança truncado."
                )

        buffer = C.create_string_buffer(data)

        if not self.a.IsValidSecurityDescriptor(buffer):
            raise BackupError(
                "Descritor de segurança rejeitado pelo Windows."
            )

        return self.descriptor_text(buffer)

    def set_basic(self, handle, metadata):
        # ChangeTime registra a nova operação de recuperação.
        value = BasicInfo(
            metadata["creation_time"],
            metadata["access_time"],
            metadata["write_time"],
            0,
            metadata["attributes"],
        )

        self.check(
            self.k.SetFileInformationByHandle(
                handle,
                0,
                C.byref(value),
                C.sizeof(value),
            )
        )

    def write_archive(
        self,
        handle,
        source,
        *,
        security=False,
    ):
        context = P()
        written = W.DWORD()
        failure = None

        try:
            source.seek(0)

            while block := source.read(65536):
                buffer = C.create_string_buffer(block)
                offset = 0

                while offset < len(block):
                    self.check(
                        self.k.BackupWrite(
                            handle,
                            C.byref(buffer, offset),
                            len(block) - offset,
                            C.byref(written),
                            False,
                            security,
                            C.byref(context),
                        )
                    )

                    if not (
                        0 < written.value
                        <= len(block) - offset
                    ):
                        raise BackupError(
                            "Gravação nativa incompleta."
                        )

                    offset += written.value

        except BaseException as error:
            failure = error
            raise

        finally:
            if not self.k.BackupWrite(
                handle,
                None,
                0,
                C.byref(written),
                True,
                security,
                C.byref(context),
            ):
                error = C.WinError(
                    C.get_last_error()
                )

                if failure is not None:
                    failure.add_note(
                        f"Liberação de BackupWrite: {error}"
                    )
                else:
                    raise error