"""Strict host prerequisites for the bounded Full C6 production path.

This module is the only host-discovery layer for the production coordinator.
It turns a raw, lexical project path and an exact resolved configuration into
ephemeral process inputs.  The result is deliberately context-managed: its two
quarantine directories exist only while the lease is active, and no report or
serialization surface exposes machine-local paths.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
import base64
import binascii
import csv
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import compat32
import hashlib
import hmac
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import shutil
import stat
import sys
import tempfile
import unicodedata
from typing import TYPE_CHECKING, SupportsIndex, cast

if TYPE_CHECKING:
    from rextio.build.full_c6_pipeline import FullC6PublicationAdapter
    from rextio.build.full_c6_production import (
        FullC6ProductionAuthority,
        _FullC6ProductionMaterial,
    )

from rextio.__about__ import __version__
from rextio.analyzer.project_namespace import has_builtin_ignored_part
from rextio.artifacts.profiles import detect_host_target_triple
from rextio.build.full_c6_cargo_workspace import (
    FullC6CargoDependencyWorkspaceReceipt,
    collect_full_c6_cargo_dependency_workspace,
    compute_full_c6_cargo_vendor_tree_sha256,
    validate_full_c6_cargo_dependency_workspace_receipt,
)
from rextio.build.full_c6_executor import FullC6NativeToolPaths
from rextio.build.full_c6_toolchain_support import (
    FullC6ToolchainSupportError,
    FullC6ToolchainSupportPlan,
    discover_full_c6_toolchain_support,
    require_full_c6_toolchain_support_plan,
    resolve_full_c6_linker_and_inspector,
    verify_full_c6_toolchain_support_lock,
)
from rextio.build.input_closure import BuildInputIdentityError
from rextio.build.subprocess_utils import run_build_tool
from rextio.build.toolchain import check_version_pin, resolve_python, resolve_tool
from rextio.build.toolchain_identity import (
    BuildToolchainIdentity,
    RextioIdentity,
    ToolchainIdentityError,
    assemble_build_toolchain_identity,
    capture_argv_identity,
    capture_cargo_sources,
    capture_environment_identity,
    capture_rextio_identity,
    capture_tool_identity,
    verify_tool_identity,
)
from rextio.build.toolchain_support_lock import (
    MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES,
    ToolchainSupportLock,
    ToolchainSupportLockError,
    parse_toolchain_support_lock,
)
from rextio.config.schema import RextioConfig


FULL_C6_HOST_INPUTS_DOMAIN = "rextio.full-c6-host-prerequisites.v1"
FULL_C6_ANALYSIS_SCOPE_DOMAIN = "rextio.full-c6-analysis-scope.v1"
FULL_C6_SOURCE_DATE_EPOCH = 0
FULL_C6_CARGO_ROOT_PACKAGE = "rextio_generated_native"
FULL_C6_CARGO_ARGUMENTS = (
    "build",
    "--release",
    "--locked",
    "--offline",
    "--frozen",
)
MAX_FULL_C6_ANALYSIS_PYTHON_FILES = 1024
MAX_FULL_C6_ANALYSIS_DIRECTORIES = 4096
MAX_FULL_C6_ANALYSIS_ENTRIES = 16384
MAX_FULL_C6_ANALYSIS_SOURCE_BYTES = 256 * 1024 * 1024
MAX_FULL_C6_ANALYSIS_RELATIVE_CHARS = 512
MAX_FULL_C6_ANALYSIS_RELATIVE_BYTES = 2048
MAX_FULL_C6_ANALYSIS_DEPTH = 32
_SUPPORTED_TARGETS = frozenset(
    {"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}
)
_RECORD_MAX_BYTES = 8 * 1024 * 1024
_RECORD_MAX_ROWS = 4096
_METADATA_MAX_BYTES = 1024 * 1024
_DIRECT_URL_MAX_BYTES = 64 * 1024
_DIRECT_URL_MAX_DEPTH = 16
_DIRECT_URL_MAX_NODES = 4096
_DISTRIBUTION_ROOT_MAX_ENTRIES = 16384
_VERSION_OUTPUT_MAX_BYTES = 64 * 1024
_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
_WHEEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\.whl$")
_SEAL_KEY = secrets.token_bytes(32)


class FullC6HostInputsError(RuntimeError):
    """A strict host prerequisite is missing, ambiguous, or unsafe."""


@dataclass(slots=True)
class _Lease:
    active: bool = True
    generation: int = 0
    quarantine_cleaned: bool = False
    publication_authority: object | None = None


@dataclass(frozen=True, slots=True)
class _DirectoryBinding:
    device: int
    inode: int
    uid: int
    mode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _DirectoryBinding:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            uid=value.st_uid,
            mode=stat.S_IMODE(value.st_mode),
        )


@dataclass(frozen=True, slots=True)
class _FileBinding:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _NamespaceDirectoryBinding:
    device: int
    inode: int
    uid: int
    mode: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _NamespaceDirectoryBinding:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            uid=value.st_uid,
            mode=stat.S_IMODE(value.st_mode),
            mtime_ns=getattr(
                value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)
            ),
            ctime_ns=getattr(
                value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000)
            ),
        )

    @property
    def stable_identity(self) -> tuple[int, int, int, int]:
        return self.device, self.inode, self.uid, self.mode


class FullC6AnalysisScope:
    """Sealed authority to exclude one verified Cargo vendor from analysis.

    A config path, ``.rextioignore`` entry, or caller-provided directory is not
    exclusion authority.  Instances exist only after the exact project root,
    typed strict config, Cargo.lock, and pinned vendor tree have been verified.
    The scanner revalidates this scope before and after discovery so a changed
    or replaced vendor cannot silently hide Python project input.
    """

    __slots__ = (
        "_cargo_workspace",
        "_config",
        "_project_binding",
        "_project_root",
        "_python_directories",
        "_python_files",
        "_seal",
        "_vendor_binding",
        "_vendor_relative",
        "_vendor_root",
    )

    _cargo_workspace: FullC6CargoDependencyWorkspaceReceipt
    _config: RextioConfig
    _project_binding: _DirectoryBinding
    _project_root: Path
    _python_directories: tuple[tuple[str, _NamespaceDirectoryBinding], ...]
    _python_files: tuple[tuple[str, _FileBinding], ...]
    _seal: bytes
    _vendor_binding: _DirectoryBinding
    _vendor_relative: str
    _vendor_root: Path

    def __init__(self) -> None:
        raise TypeError("Full C6 analysis scopes require verified Cargo authority")

    def __repr__(self) -> str:
        return "FullC6AnalysisScope(material=<sealed>)"

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("Full C6 analysis scopes are immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("Full C6 analysis scopes are immutable")

    def __copy__(self) -> object:
        raise TypeError("Full C6 analysis scopes cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("Full C6 analysis scopes cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Full C6 analysis scopes cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Full C6 analysis scopes cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("Full C6 analysis scopes cannot be serialized")


class _FullC6AnalysisNamespaceObservation:
    """Process-sealed temporal directory snapshot for one analysis call."""

    __slots__ = ("_directories", "_scope", "_seal")

    _directories: tuple[tuple[str, _NamespaceDirectoryBinding], ...]
    _scope: FullC6AnalysisScope
    _seal: bytes

    def __init__(self) -> None:
        raise TypeError("Full C6 analysis observations require sealed scope")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("Full C6 analysis observations are immutable")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Full C6 analysis observations cannot be serialized")


class FullC6PublicationPlan:
    """Ephemeral adapter plan derived from one valid publication authority."""

    __slots__ = (
        "_authority",
        "_bundle_name",
        "_final_signature_path",
        "_lease",
        "_public_key_path",
        "_publication_root",
        "_publication_binding",
        "_public_key_binding",
        "_seal",
        "_signature_binding",
        "_state_binding",
        "_state_directory",
        "_subject_binding",
        "_subject_path",
        "_wheel_filename",
    )

    _authority: object
    _bundle_name: str
    _final_signature_path: Path
    _lease: _Lease
    _public_key_path: Path
    _public_key_binding: _FileBinding
    _publication_root: Path
    _publication_binding: _DirectoryBinding
    _seal: bytes
    _signature_binding: _FileBinding
    _state_binding: _DirectoryBinding
    _state_directory: Path
    _subject_binding: _FileBinding
    _subject_path: Path
    _wheel_filename: str

    def __init__(self) -> None:
        raise TypeError("Full C6 publication plans require validated production authority")

    def __repr__(self) -> str:
        return "FullC6PublicationPlan(material=<sealed>)"

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("Full C6 publication plans are immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("Full C6 publication plans are immutable")

    def __copy__(self) -> object:
        raise TypeError("Full C6 publication plans cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("Full C6 publication plans cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Full C6 publication plans cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Full C6 publication plans cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("Full C6 publication plans cannot be serialized")

    @property
    def wheel_filename(self) -> str:
        """Return the actual retained subject-wheel filename."""
        self._require_active()
        return self._wheel_filename

    @property
    def bundle_name(self) -> str:
        """Return the deterministic publication directory name."""
        self._require_active()
        return self._bundle_name

    def atomic_adapter(self) -> FullC6PublicationAdapter:
        """Create the sealed publication adapter without serializing local paths."""
        self._require_active()
        from rextio.build.full_c6_pipeline import _full_c6_atomic_publication_adapter

        return _full_c6_atomic_publication_adapter(
            authority=cast("FullC6ProductionAuthority", self._authority),
            state_directory=self._state_directory,
            publication_root=self._publication_root,
            bundle_name=self._bundle_name,
            subject_path=self._subject_path,
            final_signature_path=self._final_signature_path,
            public_key_path=self._public_key_path,
        )

    def _require_active(self) -> None:
        if type(self._lease) is not _Lease or not self._lease.active:
            raise FullC6HostInputsError("Full C6 host prerequisite lease has ended")
        try:
            seal_valid = (
                type(self) is FullC6PublicationPlan
                and type(self._seal) is bytes
                and hmac.compare_digest(self._seal, _publication_plan_seal(self))
            )
        except Exception as exc:
            raise FullC6HostInputsError(
                "Full C6 publication plan seal is invalid"
            ) from exc
        if not seal_valid:
            raise FullC6HostInputsError("Full C6 publication plan seal is invalid")
        if (
            not self._lease.quarantine_cleaned
            or self._lease.publication_authority is not self._authority
        ):
            raise FullC6HostInputsError(
                "Full C6 publication plan lacks completed prepublication cleanup"
            )
        _verify_directory_binding(
            self._state_directory, self._state_binding, label="state"
        )
        _verify_directory_binding(
            self._publication_root,
            self._publication_binding,
            label="publication root",
        )
        _verify_file_binding(
            self._subject_path, self._subject_binding, label="retained subject wheel"
        )
        _verify_file_binding(
            self._public_key_path, self._public_key_binding, label="trusted public key"
        )
        _verify_file_binding(
            self._final_signature_path,
            self._signature_binding,
            label="final signature",
        )


class FullC6HostPrerequisites:
    """Non-serializable, context-bound inputs for the production collector."""

    __slots__ = (
        "_base_environment",
        "_cargo_workspace",
        "_config",
        "_first_quarantine_root",
        "_first_quarantine_binding",
        "_lease",
        "_native_tools",
        "_project_root",
        "_project_binding",
        "_publication_root",
        "_quarantine_container",
        "_quarantine_container_binding",
        "_second_quarantine_root",
        "_second_quarantine_binding",
        "_state_directory",
        "_state_binding",
        "_target_triple",
        "_toolchain",
        "_toolchain_support_lock",
        "_toolchain_support_lock_binding",
        "_toolchain_support_lock_path",
        "_toolchain_support_plan",
        "_seal",
    )

    _base_environment: tuple[tuple[str, str], ...]
    _cargo_workspace: FullC6CargoDependencyWorkspaceReceipt
    _config: RextioConfig
    _first_quarantine_root: Path
    _first_quarantine_binding: _DirectoryBinding
    _lease: _Lease
    _native_tools: FullC6NativeToolPaths
    _project_root: Path
    _project_binding: _DirectoryBinding
    _publication_root: Path
    _quarantine_container: Path
    _quarantine_container_binding: _DirectoryBinding
    _second_quarantine_root: Path
    _second_quarantine_binding: _DirectoryBinding
    _state_directory: Path
    _state_binding: _DirectoryBinding
    _target_triple: str
    _toolchain: BuildToolchainIdentity
    _toolchain_support_lock: ToolchainSupportLock
    _toolchain_support_lock_binding: _FileBinding
    _toolchain_support_lock_path: Path
    _toolchain_support_plan: FullC6ToolchainSupportPlan
    _seal: bytes

    def __init__(self) -> None:
        raise TypeError("Full C6 host prerequisites require the context collector")

    def __repr__(self) -> str:
        return "FullC6HostPrerequisites(material=<sealed>)"

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("Full C6 host prerequisites are immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("Full C6 host prerequisites are immutable")

    def __copy__(self) -> object:
        raise TypeError("Full C6 host prerequisites cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("Full C6 host prerequisites cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Full C6 host prerequisites cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Full C6 host prerequisites cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("Full C6 host prerequisites cannot be serialized")

    @property
    def project_root(self) -> Path:
        """Return the already-opened raw lexical project root."""
        self._require_active()
        return self._project_root

    @property
    def config(self) -> RextioConfig:
        """Return the exact typed configuration used for collection."""
        self._require_active()
        return self._config

    @property
    def target_triple(self) -> str:
        """Return the supported exact host target triple."""
        self._require_active()
        return self._target_triple

    @property
    def source_date_epoch(self) -> int:
        """Return the only permitted Full C6 reproducibility epoch."""
        self._require_active()
        return FULL_C6_SOURCE_DATE_EPOCH

    @property
    def toolchain(self) -> BuildToolchainIdentity:
        """Return the complete exact toolchain identity."""
        self._require_active()
        return self._toolchain

    @property
    def native_tools(self) -> FullC6NativeToolPaths:
        """Return ephemeral native tool paths for the executor."""
        self._require_active()
        return self._native_tools

    @property
    def toolchain_support_lock(self) -> ToolchainSupportLock:
        """Return the exact path-free support closure retained by this lease."""
        self._require_active()
        return self._toolchain_support_lock

    @property
    def toolchain_support_plan(self) -> FullC6ToolchainSupportPlan:
        """Return the exact process-sealed private support plan."""
        self._require_active()
        return require_full_c6_toolchain_support_plan(
            self._toolchain_support_plan
        )

    @property
    def cargo_workspace(self) -> FullC6CargoDependencyWorkspaceReceipt:
        """Return the process-sealed Cargo vendor workspace."""
        self._require_active()
        return self._cargo_workspace

    @property
    def first_quarantine_root(self) -> Path:
        """Return the first fresh inode-bound quarantine root."""
        self._require_active_quarantines()
        return self._first_quarantine_root

    @property
    def second_quarantine_root(self) -> Path:
        """Return the second fresh inode-bound quarantine root."""
        self._require_active_quarantines()
        return self._second_quarantine_root

    @property
    def state_directory(self) -> Path:
        """Return the persistent owner-private state directory."""
        self._require_active()
        return self._state_directory

    @property
    def base_environment(self) -> dict[str, str]:
        """Return a fresh minimal environment mapping for the executor."""
        self._require_active()
        return dict(self._base_environment)

    def production_arguments(self) -> dict[str, object]:
        """Return the exact keyword-only arguments for the production collector."""
        self._require_active_quarantines()
        return {
            "project_root": self._project_root,
            "config": self._config,
            "toolchain": self._toolchain,
            "native_tools": self._native_tools,
            "cargo_workspace": self._cargo_workspace,
            "toolchain_support_plan": self._toolchain_support_plan,
            "toolchain_support_lock": self._toolchain_support_lock,
            "first_quarantine_root": self._first_quarantine_root,
            "second_quarantine_root": self._second_quarantine_root,
            "state_directory": self._state_directory,
            "base_environment": dict(self._base_environment),
            "source_date_epoch": FULL_C6_SOURCE_DATE_EPOCH,
        }

    def complete_prepublication_cleanup(self, authority: object) -> None:
        """Irreversibly clean build quarantines before publication can begin.

        The transition is bound to the exact retained production authority and
        is idempotent only for that same object.  Once it succeeds, quarantine
        paths can no longer be obtained or reused, and context exit performs no
        further fallible filesystem cleanup.  This keeps the later atomic
        publication rename as the final fallible commit boundary.
        """
        self._require_active()
        self._require_matching_publication_material(authority)
        lease = self._lease
        if lease.quarantine_cleaned:
            if lease.publication_authority is not authority:
                raise FullC6HostInputsError(
                    "Full C6 prepublication cleanup authority changed"
                )
            return
        _remove_private_quarantine_container(
            self._quarantine_container,
            self._quarantine_container_binding,
        )
        lease.quarantine_cleaned = True
        lease.publication_authority = authority
        object.__setattr__(self, "_seal", _host_prerequisites_seal(self))
        # Revalidate all persistent bindings after cleanup.  A failure here is
        # still prepublication and context exit is already cleanup-idempotent.
        self._require_active()

    def derive_publication_plan(self, authority: object) -> FullC6PublicationPlan:
        """Bind publication to a valid final-state authority and its real wheel."""
        self._require_active()
        from rextio.build.full_c6_native_output import full_c6_native_output_wheel_path

        material = self._require_matching_publication_material(authority)
        if (
            not self._lease.quarantine_cleaned
            or self._lease.publication_authority is not authority
        ):
            raise FullC6HostInputsError(
                "Full C6 publication requires completed prepublication cleanup"
            )
        subject_path = full_c6_native_output_wheel_path(
            material.native_output_transaction
        )
        wheel_filename = subject_path.name
        if (
            not subject_path.is_absolute()
            or _lexical_absolute_path(subject_path, label="subject wheel") != subject_path
            or _WHEEL_NAME_RE.fullmatch(wheel_filename) is None
            or unicodedata.normalize("NFC", wheel_filename) != wheel_filename
        ):
            raise FullC6HostInputsError("Full C6 retained subject wheel path is invalid")
        try:
            subject_path.relative_to(self._state_directory)
        except ValueError as exc:
            raise FullC6HostInputsError(
                "Full C6 retained subject wheel escaped owner-private state"
            ) from exc
        subject_binding = _capture_file_binding(
            subject_path, label="retained subject wheel"
        )

        public_key = self._config.build.artifact_trusted_public_key
        final_signature = self._config.build.artifact_final_signature
        if type(public_key) is not str or type(final_signature) is not str:
            raise FullC6HostInputsError("Full C6 publication paths are incomplete")
        public_key_path = _configured_project_path(self._project_root, public_key)
        final_signature_path = _configured_project_path(
            self._project_root, final_signature
        )
        public_key_binding = _capture_file_binding(
            public_key_path, label="trusted public key"
        )
        signature_binding = _capture_file_binding(
            final_signature_path, label="final signature"
        )

        bundle_name = f"{wheel_filename.removesuffix('.whl')}.full-c6"
        if (
            not bundle_name
            or len(bundle_name) > 160
            or bundle_name != unicodedata.normalize("NFC", bundle_name)
        ):
            raise FullC6HostInputsError("Full C6 wheel filename cannot form a bundle name")
        publication_root = _ensure_publication_root(self._project_root)
        plan = object.__new__(FullC6PublicationPlan)
        object.__setattr__(plan, "_authority", authority)
        object.__setattr__(plan, "_lease", self._lease)
        object.__setattr__(plan, "_state_directory", self._state_directory)
        object.__setattr__(plan, "_state_binding", self._state_binding)
        object.__setattr__(plan, "_publication_root", publication_root)
        object.__setattr__(
            plan, "_publication_binding", _directory_binding(publication_root)
        )
        object.__setattr__(plan, "_bundle_name", bundle_name)
        object.__setattr__(plan, "_subject_path", subject_path)
        object.__setattr__(plan, "_subject_binding", subject_binding)
        object.__setattr__(plan, "_final_signature_path", final_signature_path)
        object.__setattr__(plan, "_signature_binding", signature_binding)
        object.__setattr__(plan, "_public_key_path", public_key_path)
        object.__setattr__(plan, "_public_key_binding", public_key_binding)
        object.__setattr__(plan, "_wheel_filename", wheel_filename)
        object.__setattr__(plan, "_seal", _publication_plan_seal(plan))
        return plan

    def _require_matching_publication_material(
        self,
        authority: object,
    ) -> _FullC6ProductionMaterial:
        material = _validated_production_material(authority)
        if material.lifecycle.status != "publication-required":
            raise FullC6HostInputsError(
                "Full C6 publication plan requires publication-required lifecycle"
            )
        if (
            material.project_root != self._project_root
            or material.config is not self._config
            or material.cargo_workspace is not self._cargo_workspace
        ):
            raise FullC6HostInputsError(
                "Full C6 production authority replaced host prerequisites"
            )
        return material

    def _require_active_quarantines(self) -> None:
        self._require_active()
        if self._lease.quarantine_cleaned:
            raise FullC6HostInputsError(
                "Full C6 prepublication quarantine cleanup is complete"
            )

    def _require_active(self) -> None:
        if type(self._lease) is not _Lease or not self._lease.active:
            raise FullC6HostInputsError("Full C6 host prerequisite lease has ended")
        try:
            seal_valid = (
                type(self) is FullC6HostPrerequisites
                and type(self._seal) is bytes
                and hmac.compare_digest(self._seal, _host_prerequisites_seal(self))
            )
        except Exception as exc:
            raise FullC6HostInputsError(
                "Full C6 host prerequisite seal is invalid"
            ) from exc
        if not seal_valid:
            raise FullC6HostInputsError("Full C6 host prerequisite seal is invalid")
        _verify_directory_binding(
            self._project_root,
            self._project_binding,
            label="project",
        )
        if not self._lease.quarantine_cleaned:
            _verify_directory_binding(
                self._quarantine_container,
                self._quarantine_container_binding,
                label="quarantine container",
            )
            _verify_directory_binding(
                self._first_quarantine_root,
                self._first_quarantine_binding,
                label="first quarantine",
            )
            _verify_directory_binding(
                self._second_quarantine_root,
                self._second_quarantine_binding,
                label="second quarantine",
            )
        _verify_directory_binding(
            self._state_directory,
            self._state_binding,
            label="state",
        )
        _verify_file_binding(
            self._toolchain_support_lock_path,
            self._toolchain_support_lock_binding,
            label="toolchain support lock",
        )
        plan = require_full_c6_toolchain_support_plan(
            self._toolchain_support_plan
        )
        if plan.target_triple != self._target_triple:
            raise FullC6HostInputsError(
                "Full C6 toolchain support plan target changed"
            )


def collect_full_c6_analysis_scope(
    project_root: Path | str,
    *,
    config: RextioConfig,
) -> FullC6AnalysisScope:
    """Seal the sole non-project Python root allowed by strict Full C6.

    Collection deliberately performs no toolchain probe and creates no build
    state.  It does fully verify the configured Cargo.lock and vendor tree,
    including the owner-pinned vendor-tree integrity checks, before the vendor
    can be excluded from initial analysis.  This does not authenticate a crate
    publisher or registry origin.
    """
    if (
        type(config) is not RextioConfig
        or config.build.artifact_distribution_policy != "full-c6-required"
    ):
        raise FullC6HostInputsError(
            "Full C6 analysis scope requires exact strict typed config"
        )
    root, project_binding = _open_raw_project_root(project_root)
    _verify_directory_binding(root, project_binding, label="project")
    _validate_host_layout(root, config)
    cargo_workspace = _collect_configured_cargo_workspace(root, config)
    vendor_relative = config.build.artifact_cargo_vendor
    if type(vendor_relative) is not str:
        raise FullC6HostInputsError("Full C6 analysis vendor path is unavailable")
    vendor_root = _configured_project_path(root, vendor_relative)
    vendor_binding = _require_secure_directory(
        vendor_root,
        label="analysis Cargo vendor",
    )
    python_files, python_directories = _collect_full_c6_project_python_namespace(
        root,
        vendor_root=vendor_root,
    )
    scope = object.__new__(FullC6AnalysisScope)
    object.__setattr__(scope, "_project_root", root)
    object.__setattr__(scope, "_project_binding", project_binding)
    object.__setattr__(scope, "_python_directories", python_directories)
    object.__setattr__(scope, "_python_files", python_files)
    object.__setattr__(scope, "_config", config)
    object.__setattr__(scope, "_cargo_workspace", cargo_workspace)
    object.__setattr__(scope, "_vendor_relative", vendor_relative)
    object.__setattr__(scope, "_vendor_root", vendor_root)
    object.__setattr__(scope, "_vendor_binding", vendor_binding)
    object.__setattr__(scope, "_seal", _analysis_scope_seal(scope))
    _require_full_c6_analysis_scope(
        scope,
        project_root=root,
        config=config,
        revalidate_workspace=False,
    )
    return scope


def require_full_c6_analysis_scope(
    value: object,
    *,
    project_root: Path | str,
    config: RextioConfig,
) -> Path:
    """Revalidate a scope and return its exact lexical vendor root internally."""
    return _require_full_c6_analysis_scope(
        value,
        project_root=project_root,
        config=config,
        revalidate_workspace=True,
    )


def require_full_c6_analysis_files(
    value: object,
    *,
    project_root: Path | str,
    config: RextioConfig,
) -> tuple[Path, ...]:
    """Return only the exact sealed Python path set after full revalidation."""
    _require_full_c6_analysis_scope(
        value,
        project_root=project_root,
        config=config,
        revalidate_workspace=True,
    )
    assert type(value) is FullC6AnalysisScope
    return tuple(
        value._project_root.joinpath(*PurePosixPath(relative).parts)
        for relative, _binding in value._python_files
    )


def begin_full_c6_analysis_namespace(
    value: object,
    *,
    project_root: Path | str,
    config: RextioConfig,
) -> object:
    """Open a temporal namespace observation around one strict analysis."""
    _require_full_c6_analysis_scope(
        value,
        project_root=project_root,
        config=config,
        revalidate_workspace=True,
    )
    assert type(value) is FullC6AnalysisScope
    directories = _capture_analysis_scope_directories(value)
    observation = object.__new__(_FullC6AnalysisNamespaceObservation)
    object.__setattr__(observation, "_scope", value)
    object.__setattr__(observation, "_directories", directories)
    object.__setattr__(observation, "_seal", _analysis_observation_seal(observation))
    return observation


def finish_full_c6_analysis_namespace(
    value: object,
    observation: object,
    *,
    project_root: Path | str,
    config: RextioConfig,
) -> None:
    """Close one observation and reject any transient directory mutation."""
    if (
        type(value) is not FullC6AnalysisScope
        or type(observation) is not _FullC6AnalysisNamespaceObservation
        or observation._scope is not value
        or type(observation._seal) is not bytes
        or not hmac.compare_digest(
            observation._seal,
            _analysis_observation_seal(observation),
        )
    ):
        raise FullC6HostInputsError("Full C6 analysis observation is invalid")
    _require_full_c6_analysis_scope(
        value,
        project_root=project_root,
        config=config,
        revalidate_workspace=True,
    )
    if _capture_analysis_scope_directories(value) != observation._directories:
        raise FullC6HostInputsError(
            "Full C6 project Python directory changed during analysis"
        )


def _capture_analysis_scope_directories(
    scope: FullC6AnalysisScope,
) -> tuple[tuple[str, _NamespaceDirectoryBinding], ...]:
    return tuple(
        (
            relative,
            _capture_namespace_directory_binding(
                _namespace_directory_path(scope._project_root, relative),
                label="analysis project Python directory",
            ),
        )
        for relative, _binding in scope._python_directories
    )


def _require_full_c6_analysis_scope(
    value: object,
    *,
    project_root: Path | str,
    config: RextioConfig,
    revalidate_workspace: bool,
) -> Path:
    if type(value) is not FullC6AnalysisScope or type(config) is not RextioConfig:
        raise FullC6HostInputsError("Full C6 analysis scope is invalid")
    try:
        root = _lexical_absolute_path(project_root, label="analysis project root")
        seal_valid = type(value._seal) is bytes and hmac.compare_digest(
            value._seal,
            _analysis_scope_seal(value),
        )
    except Exception as exc:
        raise FullC6HostInputsError("Full C6 analysis scope is invalid") from exc
    if (
        not seal_valid
        or value._config is not config
        or config.build.artifact_distribution_policy != "full-c6-required"
        or value._project_root != root
        or type(value._cargo_workspace)
        is not FullC6CargoDependencyWorkspaceReceipt
        or not validate_full_c6_cargo_dependency_workspace_receipt(
            value._cargo_workspace
        )
    ):
        raise FullC6HostInputsError("Full C6 analysis scope is stale or foreign")
    vendor_relative = config.build.artifact_cargo_vendor
    if (
        type(vendor_relative) is not str
        or value._vendor_relative != vendor_relative
    ):
        raise FullC6HostInputsError("Full C6 analysis scope is stale or foreign")
    expected_vendor = _configured_project_path(root, vendor_relative)
    if value._vendor_root != expected_vendor:
        raise FullC6HostInputsError("Full C6 analysis scope vendor changed")
    _verify_directory_binding(root, value._project_binding, label="analysis project")
    _verify_directory_binding(
        expected_vendor,
        value._vendor_binding,
        label="analysis Cargo vendor",
    )
    _require_strict_rextioignore_absent(root)
    _verify_full_c6_project_python_namespace(
        root,
        vendor_root=expected_vendor,
        expected_files=value._python_files,
        expected_directories=value._python_directories,
    )
    if revalidate_workspace:
        fresh_workspace = _collect_configured_cargo_workspace(root, config)
        if not hmac.compare_digest(
            fresh_workspace.digest,
            value._cargo_workspace.digest,
        ):
            raise FullC6HostInputsError("Full C6 analysis Cargo authority changed")
    return expected_vendor


def _collect_full_c6_project_python_namespace(
    root: Path,
    *,
    vendor_root: Path,
) -> tuple[
    tuple[tuple[str, _FileBinding], ...],
    tuple[tuple[str, _NamespaceDirectoryBinding], ...],
]:
    """Capture the exact built-in-filtered project Python namespace."""
    relative_paths = _discover_full_c6_project_python_paths(
        root,
        vendor_root=vendor_root,
    )
    bound_files: list[tuple[str, _FileBinding]] = []
    aggregate_bytes = 0
    for relative in relative_paths:
        binding = _capture_file_binding(
            root.joinpath(*PurePosixPath(relative).parts),
            label="analysis project Python source",
        )
        aggregate_bytes += binding.size
        if aggregate_bytes > MAX_FULL_C6_ANALYSIS_SOURCE_BYTES:
            raise FullC6HostInputsError(
                "Full C6 project Python source bytes exceed the bounded limit"
            )
        bound_files.append((relative, binding))
    bindings = tuple(bound_files)
    directory_bindings = tuple(
        (
            relative,
            _capture_namespace_directory_binding(
                _namespace_directory_path(root, relative),
                label="analysis project Python directory",
            ),
        )
        for relative in _python_namespace_directory_paths(relative_paths)
    )
    _verify_full_c6_project_python_namespace(
        root,
        vendor_root=vendor_root,
        expected_files=bindings,
        expected_directories=directory_bindings,
    )
    return bindings, directory_bindings


def _verify_full_c6_project_python_namespace(
    root: Path,
    *,
    vendor_root: Path,
    expected_files: tuple[tuple[str, _FileBinding], ...],
    expected_directories: tuple[tuple[str, _NamespaceDirectoryBinding], ...],
) -> None:
    observed_paths = _discover_full_c6_project_python_paths(
        root,
        vendor_root=vendor_root,
    )
    expected_paths = tuple(relative for relative, _binding in expected_files)
    if observed_paths != expected_paths:
        raise FullC6HostInputsError("Full C6 project Python namespace changed")
    observed_directory_paths = _python_namespace_directory_paths(observed_paths)
    expected_directory_paths = tuple(
        relative for relative, _binding in expected_directories
    )
    if observed_directory_paths != expected_directory_paths:
        raise FullC6HostInputsError("Full C6 project Python directory set changed")
    for relative, directory_binding in expected_directories:
        observed = _capture_namespace_directory_binding(
            _namespace_directory_path(root, relative),
            label="analysis project Python directory",
        )
        # Full C6 itself may create fixed built-in-ignored roots (``.rextio``
        # and ``dist``) between analyses, which legitimately changes only the
        # project root timestamps.  Root replacement is still blocked by the
        # stable identity; exact source-file ctime/inode bindings catch a
        # transient root-level Python move.  Every nested source directory is
        # held to the complete temporal binding.
        if relative == "":
            if observed.stable_identity != directory_binding.stable_identity:
                raise FullC6HostInputsError(
                    "Full C6 project Python root directory changed"
                )
        elif observed != directory_binding:
            raise FullC6HostInputsError(
                "Full C6 project Python directory changed"
            )
    for relative, file_binding in expected_files:
        _verify_file_binding(
            root.joinpath(*PurePosixPath(relative).parts),
            file_binding,
            label="analysis project Python source",
        )


def _python_namespace_directory_paths(
    python_paths: tuple[str, ...],
) -> tuple[str, ...]:
    directories = {""}
    for relative in python_paths:
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return tuple(sorted(directories))


def _namespace_directory_path(root: Path, relative: str) -> Path:
    if relative == "":
        return root
    return root.joinpath(*PurePosixPath(relative).parts)


def _discover_full_c6_project_python_paths(
    root: Path,
    *,
    vendor_root: Path,
) -> tuple[str, ...]:
    """Discover names for collection/validation, never for scanner authority."""
    discovered: list[str] = []
    traversed_directories = 1
    observed_entries = 0
    pending = [root]
    try:
        while pending:
            current = pending.pop()
            descriptor = _open_absolute_directory_no_follow(
                current,
                label="analysis project Python namespace",
            )
            try:
                with os.scandir(descriptor) as iterator:
                    entries = iterator
                    for entry in entries:
                        observed_entries += 1
                        if observed_entries > MAX_FULL_C6_ANALYSIS_ENTRIES:
                            raise FullC6HostInputsError(
                                "Full C6 project namespace entries exceed the bounded limit"
                            )
                        name = entry.name
                        if (
                            not name
                            or name in {".", ".."}
                            or name != unicodedata.normalize("NFC", name)
                            or "/" in name
                            or "\\" in name
                        ):
                            raise FullC6HostInputsError(
                                "Full C6 project namespace entry is invalid"
                            )
                        candidate = current / name
                        relative = candidate.relative_to(root)
                        if has_builtin_ignored_part(relative):
                            continue
                        if candidate == vendor_root or candidate.is_relative_to(
                            vendor_root
                        ):
                            continue
                        try:
                            observed = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            raise FullC6HostInputsError(
                                "Full C6 project namespace changed during discovery"
                            ) from exc
                        if stat.S_ISLNK(observed.st_mode):
                            raise FullC6HostInputsError(
                                "Full C6 project Python namespace contains a path alias"
                            )
                        if stat.S_ISDIR(observed.st_mode):
                            traversed_directories += 1
                            if (
                                traversed_directories
                                > MAX_FULL_C6_ANALYSIS_DIRECTORIES
                            ):
                                raise FullC6HostInputsError(
                                    "Full C6 project Python directories exceed the bounded limit"
                                )
                            pending.append(candidate)
                            continue
                        if not stat.S_ISREG(observed.st_mode):
                            raise FullC6HostInputsError(
                                "Full C6 project Python namespace contains a special entry"
                            )
                        if not name.endswith(".py"):
                            continue
                        logical = relative.as_posix()
                        if (
                            not logical
                            or logical != unicodedata.normalize("NFC", logical)
                            or "\\" in logical
                            or any(
                                part in {"", ".", ".."}
                                for part in PurePosixPath(logical).parts
                            )
                        ):
                            raise FullC6HostInputsError(
                                "Full C6 project Python namespace path is invalid"
                            )
                        if (
                            len(logical) > MAX_FULL_C6_ANALYSIS_RELATIVE_CHARS
                            or len(logical.encode("utf-8"))
                            > MAX_FULL_C6_ANALYSIS_RELATIVE_BYTES
                            or len(PurePosixPath(logical).parts)
                            > MAX_FULL_C6_ANALYSIS_DEPTH
                        ):
                            raise FullC6HostInputsError(
                                "Full C6 project Python path exceeds the bounded limit"
                            )
                        discovered.append(logical)
                        if len(discovered) > MAX_FULL_C6_ANALYSIS_PYTHON_FILES:
                            raise FullC6HostInputsError(
                                "Full C6 project Python files exceed the bounded limit"
                            )
            finally:
                os.close(descriptor)
    except FullC6HostInputsError:
        raise
    except OSError as exc:
        raise FullC6HostInputsError(
            "Full C6 project Python namespace could not be discovered"
        ) from exc
    ordered = tuple(sorted(discovered))
    if len(ordered) != len(set(ordered)):
        raise FullC6HostInputsError("Full C6 project Python namespace is ambiguous")
    return ordered


@contextmanager
def collect_full_c6_host_prerequisites(
    project_root: Path | str,
    *,
    config: RextioConfig,
    inherited_environment: Mapping[str, str] | None = None,
) -> Iterator[FullC6HostPrerequisites]:
    """Collect one strict host lease for CPython 3.11 on two Alpha targets."""
    if type(config) is not RextioConfig:
        raise FullC6HostInputsError("Full C6 host collection requires exact typed config")
    root, root_binding = _open_raw_project_root(project_root)
    _verify_directory_binding(root, root_binding, label="project")
    target_triple = _require_supported_host()
    inherited = _validate_inherited_environment(inherited_environment)
    _validate_host_layout(root, config)

    support_lock, support_lock_path, support_lock_binding = (
        _collect_configured_toolchain_support_lock(
            root,
            config,
            target_triple=target_triple,
        )
    )

    cargo_workspace = _collect_configured_cargo_workspace(root, config)
    native_tools, toolchain, base_environment, support_plan = _collect_toolchain(
        root=root,
        config=config,
        target_triple=target_triple,
        inherited=inherited,
        cargo_workspace=cargo_workspace,
        support_lock=support_lock,
    )
    if toolchain.cargo_sources is not cargo_workspace.cargo_sources:
        raise FullC6HostInputsError(
            "Full C6 toolchain did not retain exact Cargo workspace sources"
        )

    state_directory = _ensure_state_directory(root, config)
    publication_root = root / "dist"
    lease = _Lease()
    container, container_binding, first, first_binding, second, second_binding = (
        _create_quarantine_lease(root)
    )
    prerequisites = object.__new__(FullC6HostPrerequisites)
    object.__setattr__(prerequisites, "_lease", lease)
    object.__setattr__(prerequisites, "_project_root", root)
    object.__setattr__(prerequisites, "_project_binding", root_binding)
    object.__setattr__(prerequisites, "_config", config)
    object.__setattr__(prerequisites, "_target_triple", target_triple)
    object.__setattr__(prerequisites, "_toolchain", toolchain)
    object.__setattr__(prerequisites, "_toolchain_support_lock", support_lock)
    object.__setattr__(prerequisites, "_toolchain_support_plan", support_plan)
    object.__setattr__(
        prerequisites,
        "_toolchain_support_lock_path",
        support_lock_path,
    )
    object.__setattr__(
        prerequisites,
        "_toolchain_support_lock_binding",
        support_lock_binding,
    )
    object.__setattr__(prerequisites, "_native_tools", native_tools)
    object.__setattr__(prerequisites, "_cargo_workspace", cargo_workspace)
    object.__setattr__(prerequisites, "_first_quarantine_root", first)
    object.__setattr__(prerequisites, "_first_quarantine_binding", first_binding)
    object.__setattr__(prerequisites, "_second_quarantine_root", second)
    object.__setattr__(prerequisites, "_second_quarantine_binding", second_binding)
    object.__setattr__(prerequisites, "_state_directory", state_directory)
    object.__setattr__(
        prerequisites, "_state_binding", _directory_binding(state_directory)
    )
    object.__setattr__(prerequisites, "_publication_root", publication_root)
    object.__setattr__(prerequisites, "_quarantine_container", container)
    object.__setattr__(
        prerequisites,
        "_quarantine_container_binding",
        container_binding,
    )
    object.__setattr__(
        prerequisites, "_base_environment", tuple(sorted(base_environment.items()))
    )
    object.__setattr__(
        prerequisites, "_seal", _host_prerequisites_seal(prerequisites)
    )
    raised = False
    try:
        _verify_directory_binding(first, first_binding, label="first quarantine")
        _verify_directory_binding(second, second_binding, label="second quarantine")
        yield prerequisites
    except BaseException:
        raised = True
        raise
    finally:
        lease.active = False
        lease.generation += 1
        # Context exit is irreversible.  Invalidate rather than recomputing a
        # semantic HMAC so no fallible projection work can follow a committed
        # publication; direct reactivation then fails the seal check.
        object.__setattr__(prerequisites, "_seal", b"")
        if not lease.quarantine_cleaned:
            try:
                _remove_private_quarantine_container(container, container_binding)
            except FullC6HostInputsError:
                if not raised:
                    raise


def _require_supported_host() -> str:
    if platform.python_implementation() != "CPython" or sys.version_info[:2] != (3, 11):
        raise FullC6HostInputsError("Full C6 host production requires CPython 3.11 exactly")
    try:
        target = detect_host_target_triple()
    except ValueError as exc:
        raise FullC6HostInputsError("Full C6 host target could not be resolved") from exc
    if target not in _SUPPORTED_TARGETS:
        raise FullC6HostInputsError(
            "Full C6 host production supports only macOS arm64 and Linux x86_64"
        )
    return target


def _open_raw_project_root(value: Path | str) -> tuple[Path, _DirectoryBinding]:
    root = _lexical_absolute_path(value, label="project root")
    descriptor = _open_absolute_directory_no_follow(root, label="project root")
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISDIR(observed.st_mode):
            raise FullC6HostInputsError("Full C6 project root is not a directory")
        return root, _DirectoryBinding.from_stat(observed)
    finally:
        os.close(descriptor)


def _collect_configured_cargo_workspace(
    root: Path,
    config: RextioConfig,
) -> FullC6CargoDependencyWorkspaceReceipt:
    build = config.build
    lock_relative = build.artifact_cargo_lock
    lock_sha256 = build.artifact_cargo_lock_sha256
    vendor_relative = build.artifact_cargo_vendor
    vendor_sha256 = build.artifact_cargo_vendor_sha256
    if (
        type(lock_relative) is not str
        or not lock_relative
        or type(lock_sha256) is not str
        or not lock_sha256
        or type(vendor_relative) is not str
        or not vendor_relative
        or type(vendor_sha256) is not str
        or not vendor_sha256
    ):
        raise FullC6HostInputsError("Full C6 Cargo lock/vendor paths and pins are required")
    lock_path = _configured_project_path(root, lock_relative)
    vendor_path = _configured_project_path(root, vendor_relative)
    _require_secure_regular_file(lock_path, label="Cargo.lock")
    _require_secure_directory(vendor_path, label="Cargo vendor")
    try:
        sources = capture_cargo_sources(
            lock_path,
            root_package=FULL_C6_CARGO_ROOT_PACKAGE,
        )
        if not _digest_equal(sources.lock_file.sha256, lock_sha256):
            raise FullC6HostInputsError("configured Cargo.lock SHA-256 differs from bytes")
        observed_vendor = compute_full_c6_cargo_vendor_tree_sha256(vendor_path)
        if not _digest_equal(observed_vendor, vendor_sha256):
            raise FullC6HostInputsError("configured Cargo vendor SHA-256 differs from tree")
        workspace = collect_full_c6_cargo_dependency_workspace(
            vendor_root=vendor_path,
            cargo_lock=lock_path,
            cargo_sources=sources,
            expected_vendor_tree_sha256=vendor_sha256,
        )
    except FullC6HostInputsError:
        raise
    except Exception as exc:
        raise FullC6HostInputsError("Full C6 Cargo workspace failed closed") from exc
    if not validate_full_c6_cargo_dependency_workspace_receipt(workspace):
        raise FullC6HostInputsError("Full C6 Cargo workspace receipt is stale")
    return workspace


def _collect_configured_toolchain_support_lock(
    root: Path,
    config: RextioConfig,
    *,
    target_triple: str,
) -> tuple[ToolchainSupportLock, Path, _FileBinding]:
    """Securely open, pin, parse, and retain the configured support lock."""
    relative = config.build.artifact_toolchain_support_lock
    expected_sha256 = config.build.artifact_toolchain_support_lock_sha256
    if (
        type(relative) is not str
        or not relative
        or type(expected_sha256) is not str
        or not expected_sha256
    ):
        raise FullC6HostInputsError(
            "Full C6 toolchain support lock path and SHA-256 are required"
        )
    path = _configured_project_path(root, relative)
    data, observed = _secure_read_regular(
        path,
        label="toolchain support lock",
        max_bytes=MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES,
        reject_hardlinks=True,
    )
    try:
        support_lock = parse_toolchain_support_lock(
            data,
            expected_raw_sha256=expected_sha256,
        )
    except ToolchainSupportLockError as exc:
        raise FullC6HostInputsError(
            "Full C6 toolchain support lock failed closed"
        ) from exc
    if support_lock.scope.target_triple != target_triple:
        raise FullC6HostInputsError(
            "Full C6 toolchain support lock target differs from the host"
        )
    binding = _file_binding_from_read(data, observed)
    if not _digest_equal(binding.sha256, expected_sha256):
        raise FullC6HostInputsError(
            "Full C6 toolchain support lock SHA-256 differs from bytes"
        )
    return support_lock, path, binding


def _validated_production_material(authority: object) -> _FullC6ProductionMaterial:
    """Return private material only after the production module's full validator."""
    from rextio.build import full_c6_production as production

    if (
        type(authority) is not production.FullC6ProductionAuthority
        or not production.validate_full_c6_production_authority(authority)
    ):
        raise FullC6HostInputsError(
            "Full C6 publication requires valid production authority"
        )
    return authority._material


def _validate_host_layout(root: Path, config: RextioConfig) -> None:
    """Reject overlap among persistent output state and pinned Cargo inputs."""
    if config.build.artifact_distribution_policy == "full-c6-required":
        _require_strict_rextioignore_absent(root)
    request = config.build.artifact_signing_request_output
    vendor = config.build.artifact_cargo_vendor
    lock = config.build.artifact_cargo_lock
    support_lock = config.build.artifact_toolchain_support_lock
    if (
        type(request) is not str
        or type(vendor) is not str
        or type(lock) is not str
        or type(support_lock) is not str
    ):
        # The dedicated collectors retain the actionable missing-input errors.
        return
    state = _configured_project_path(root, request).parent
    publication = root / "dist"
    vendor_path = _configured_project_path(root, vendor)
    lock_path = _configured_project_path(root, lock)
    support_lock_path = _configured_project_path(root, support_lock)
    directories = (state, publication, vendor_path)
    for index, path in enumerate(directories):
        for other in directories[index + 1 :]:
            if path == other or path in other.parents or other in path.parents:
                raise FullC6HostInputsError(
                    "Full C6 state, publication, and Cargo vendor paths must not overlap"
                )
    if any(lock_path == path or path in lock_path.parents or lock_path in path.parents for path in directories):
        raise FullC6HostInputsError(
            "Full C6 Cargo.lock must not overlap state, publication, or vendor paths"
        )
    if any(
        support_lock_path == path
        or path in support_lock_path.parents
        or support_lock_path in path.parents
        for path in (*directories, lock_path)
    ):
        raise FullC6HostInputsError(
            "Full C6 toolchain support lock must not overlap state, publication, "
            "Cargo.lock, or vendor paths"
        )


def _require_strict_rextioignore_absent(root: Path) -> None:
    """Reject the unbound custom ignore channel in strict Full C6 analysis."""
    descriptor = _open_absolute_directory_no_follow(
        root,
        label="strict project root",
    )
    try:
        try:
            os.stat(
                ".rextioignore",
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        except OSError as exc:
            raise FullC6HostInputsError(
                "Full C6 could not verify the custom ignore policy"
            ) from exc
        raise FullC6HostInputsError(
            "Full C6 forbids a custom .rextioignore because it is not build authority"
        )
    finally:
        os.close(descriptor)


def _collect_toolchain(
    *,
    root: Path,
    config: RextioConfig,
    target_triple: str,
    inherited: Mapping[str, str],
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt,
    support_lock: ToolchainSupportLock,
) -> tuple[
    FullC6NativeToolPaths,
    BuildToolchainIdentity,
    dict[str, str],
    FullC6ToolchainSupportPlan,
]:
    selected_python = _resolve_python(config)
    selected_cargo = _resolve_required_tool("cargo", config.toolchain.cargo)
    python_path = _resolve_executable(selected_python)
    cargo_path, rustc_path = _resolve_actual_rust_tools(
        selected_cargo,
        root=root,
        config=config,
        inherited=inherited,
    )
    try:
        linker_path, inspector_path = resolve_full_c6_linker_and_inspector(
            target_triple=target_triple,
            cwd=root,
        )
    except FullC6ToolchainSupportError as exc:
        raise FullC6HostInputsError(
            "Full C6 linker or native inspector discovery failed closed"
        ) from exc
    actual_paths = (
        python_path,
        cargo_path,
        rustc_path,
        linker_path,
        inspector_path,
    )
    try:
        if Path(sys.executable).resolve(strict=True) != python_path:
            raise FullC6HostInputsError(
                "Full C6 configured Python differs from the running interpreter"
            )
    except OSError as exc:
        raise FullC6HostInputsError("Full C6 running Python is unavailable") from exc

    preliminary_environment = _minimal_build_environment(cargo_path)
    probe_environment = {
        **preliminary_environment,
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": "0",
        "TZ": "UTC",
    }
    versions = (
        _probe_version(python_path, root=root, environment=probe_environment),
        _probe_version(cargo_path, root=root, environment=probe_environment),
        _probe_version(rustc_path, root=root, environment=probe_environment),
        _probe_version(linker_path, root=root, environment=probe_environment),
        _probe_version(inspector_path, root=root, environment=probe_environment),
    )
    if _probe_rustc_host(
        rustc_path, root=root, environment=probe_environment
    ) != target_triple:
        raise FullC6HostInputsError("Full C6 rustc host differs from target triple")
    _require_version_pin("CPython", versions[0], config.toolchain.python_version)
    _require_version_pin("cargo", versions[1], config.toolchain.cargo_version)
    rextio_identity = _capture_installed_rextio_identity()
    inspector_name = "otool" if target_triple.endswith("apple-darwin") else "readelf"
    try:
        python_identity = capture_tool_identity(
            "python", python_path, reported_version=versions[0]
        )
        cargo_identity = capture_tool_identity(
            "cargo", cargo_path, reported_version=versions[1]
        )
        rustc_identity = capture_tool_identity(
            "rustc", rustc_path, reported_version=versions[2]
        )
        linker_identity = capture_tool_identity(
            "linker", linker_path, reported_version=versions[3]
        )
        inspector_identity = capture_tool_identity(
            inspector_name, inspector_path, reported_version=versions[4]
        )
        identities = (
            python_identity,
            cargo_identity,
            rustc_identity,
            linker_identity,
            inspector_identity,
        )
        repeated_versions = tuple(
            _probe_version(path, root=root, environment=probe_environment)
            for path in actual_paths
        )
        if repeated_versions != versions:
            raise FullC6HostInputsError(
                "Full C6 tool version changed during exact identity capture"
            )
        if _probe_rustc_host(
            rustc_path, root=root, environment=probe_environment
        ) != target_triple:
            raise FullC6HostInputsError(
                "Full C6 rustc host changed during exact identity capture"
            )
        for path, identity in zip(actual_paths, identities, strict=True):
            verify_tool_identity(path, identity)
        support_plan = discover_full_c6_toolchain_support(
            target_triple=target_triple,
            cwd=root,
            python=python_path,
            cargo=cargo_path,
            rustc=rustc_path,
            linker=linker_path,
            inspector=inspector_path,
            platform_inspector_identity=(
                inspector_identity
                if target_triple.endswith("apple-darwin")
                else None
            ),
        )
        if not verify_full_c6_toolchain_support_lock(
            support_plan,
            support_lock,
        ):
            raise FullC6ToolchainSupportError(
                "Full C6 toolchain support lock verification failed"
            )
        base_environment = support_plan.base_environment
        final_probe_environment = {
            **base_environment,
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": "0",
            "TZ": "UTC",
        }
        final_versions = tuple(
            _probe_version(path, root=root, environment=final_probe_environment)
            for path in actual_paths
        )
        if final_versions != versions or _probe_rustc_host(
            rustc_path,
            root=root,
            environment=final_probe_environment,
        ) != target_triple:
            raise FullC6HostInputsError(
                "Full C6 tool identity changed under the fixed support environment"
            )
        argv = capture_argv_identity(("cargo", *FULL_C6_CARGO_ARGUMENTS))
        environment_identity = capture_environment_identity(base_environment)
        toolchain = assemble_build_toolchain_identity(
            python=python_identity,
            rextio=rextio_identity,
            cargo=cargo_identity,
            rustc=rustc_identity,
            linker=linker_identity,
            inspectors=(inspector_identity,),
            argv=argv,
            environment=environment_identity,
            cargo_sources=cargo_workspace.cargo_sources,
            support_plan_sha256=support_plan.digest,
            support_lock_raw_sha256=support_lock.raw_sha256,
            support_lock_merkle_sha256=support_lock.merkle_sha256,
        )
    except (
        BuildInputIdentityError,
        FullC6ToolchainSupportError,
        ToolchainIdentityError,
        TypeError,
        ValueError,
    ) as exc:
        raise FullC6HostInputsError("Full C6 toolchain identity failed closed") from exc
    native_tools = FullC6NativeToolPaths(
        python=python_path,
        cargo=cargo_path,
        rustc=rustc_path,
        linker=linker_path,
    )
    return native_tools, toolchain, base_environment, support_plan


def _resolve_python(config: RextioConfig) -> Path:
    if config.toolchain.python is None:
        return Path(sys.executable).absolute()
    path, error = resolve_python(config.toolchain)
    if path is None:
        raise FullC6HostInputsError(error or "configured Python could not be resolved")
    return Path(path).absolute()


def _resolve_required_tool(name: str, configured: str | None) -> Path:
    path, error = resolve_tool(name, configured)
    if path is None:
        raise FullC6HostInputsError(error or f"Full C6 required {name} is unavailable")
    return Path(path).absolute()


def _resolve_rustc(cargo: Path, inherited: Mapping[str, str]) -> Path:
    sibling = cargo.parent / "rustc"
    if sibling.is_file() and os.access(sibling, os.X_OK):
        return sibling.absolute()
    found = shutil.which("rustc", path=inherited.get("PATH"))
    if found is None:
        raise FullC6HostInputsError("Full C6 rustc could not be resolved beside Cargo or on PATH")
    return Path(found).absolute()


def _resolve_actual_rust_tools(
    selected_cargo: Path,
    *,
    root: Path,
    config: RextioConfig,
    inherited: Mapping[str, str],
) -> tuple[Path, Path]:
    selected_stat = _lstat_selected_executable(selected_cargo, label="selected Cargo")
    resolved_selection = _resolve_executable(selected_cargo)
    if stat.S_ISLNK(selected_stat.st_mode):
        if _symlink_target_name(selected_cargo) != "rustup":
            raise FullC6HostInputsError(
                "Full C6 rejects non-rustup Cargo executable symlinks"
            )
        rustup_proxy = selected_cargo.parent / "rustup"
        _lstat_selected_executable(rustup_proxy, label="selected rustup")
        if _resolve_executable(rustup_proxy) != resolved_selection:
            raise FullC6HostInputsError(
                "Full C6 Cargo proxy does not share one verified rustup executable"
            )
        environment = _rustup_selection_environment(
            selected_cargo=selected_cargo,
            config=config,
            inherited=inherited,
        )
        first = (
            _rustup_which(
                rustup_proxy,
                "cargo",
                root=root,
                environment=environment,
            ),
            _rustup_which(
                rustup_proxy,
                "rustc",
                root=root,
                environment=environment,
            ),
        )
        second = (
            _rustup_which(
                rustup_proxy,
                "cargo",
                root=root,
                environment=environment,
            ),
            _rustup_which(
                rustup_proxy,
                "rustc",
                root=root,
                environment=environment,
            ),
        )
        if first != second or first[0] == first[1]:
            raise FullC6HostInputsError("Full C6 rustup tool selection is ambiguous")
        return first

    cargo = resolved_selection
    selected_rustc = _resolve_rustc(cargo, inherited)
    rustc_stat = _lstat_selected_executable(selected_rustc, label="selected rustc")
    if stat.S_ISLNK(rustc_stat.st_mode):
        raise FullC6HostInputsError(
            "Full C6 rejects rustc symlinks outside a verified rustup selection"
        )
    rustc = _resolve_executable(selected_rustc)
    if cargo == rustc:
        raise FullC6HostInputsError("Full C6 Cargo and rustc executables are ambiguous")
    return cargo, rustc


def _resolve_executable(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        observed = _lstat_selected_executable(resolved, label="native tool")
    except OSError as exc:
        raise FullC6HostInputsError("Full C6 native tool is unavailable") from exc
    if not stat.S_ISREG(observed.st_mode) or not os.access(resolved, os.X_OK):
        raise FullC6HostInputsError("Full C6 native tool is not an executable file")
    return resolved


def _minimal_build_environment(cargo: Path) -> dict[str, str]:
    return {"PATH": os.fspath(cargo.parent)}


def _lstat_selected_executable(path: Path, *, label: str) -> os.stat_result:
    lexical = _lexical_absolute_path(path, label=label)
    parent_fd = _open_absolute_directory_no_follow(lexical.parent, label=f"{label} parent")
    try:
        observed = os.stat(lexical.name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise FullC6HostInputsError(f"Full C6 {label} is unavailable") from exc
    finally:
        os.close(parent_fd)
    if not (stat.S_ISREG(observed.st_mode) or stat.S_ISLNK(observed.st_mode)):
        raise FullC6HostInputsError(f"Full C6 {label} is not an executable file")
    if not os.access(lexical, os.X_OK):
        raise FullC6HostInputsError(f"Full C6 {label} is not executable")
    return observed


def _symlink_target_name(path: Path) -> str:
    parent_fd = _open_absolute_directory_no_follow(
        path.parent, label="selected symlink parent"
    )
    try:
        before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISLNK(before.st_mode):
            raise FullC6HostInputsError("Full C6 selected executable is not a symlink")
        target = os.readlink(path.name, dir_fd=parent_fd)
        after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if _stat_key(before) != _stat_key(after):
            raise FullC6HostInputsError("Full C6 selected executable symlink changed")
    except FullC6HostInputsError:
        raise
    except OSError as exc:
        raise FullC6HostInputsError(
            "Full C6 selected executable symlink could not be read"
        ) from exc
    finally:
        os.close(parent_fd)
    return Path(target).name


def _rustup_selection_environment(
    *,
    selected_cargo: Path,
    config: RextioConfig,
    inherited: Mapping[str, str],
) -> dict[str, str]:
    raw_home = inherited.get("RUSTUP_HOME")
    rustup_home = Path(raw_home) if raw_home else Path.home() / ".rustup"
    rustup_home = _lexical_absolute_path(rustup_home, label="RUSTUP_HOME")
    _require_secure_directory(rustup_home, label="RUSTUP_HOME")
    environment = {
        "PATH": os.fspath(selected_cargo.parent),
        "RUSTUP_HOME": os.fspath(rustup_home),
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    if config.toolchain.rust_toolchain is not None:
        environment["RUSTUP_TOOLCHAIN"] = config.toolchain.rust_toolchain
    return environment


def _rustup_which(
    rustup: Path,
    tool: str,
    *,
    root: Path,
    environment: Mapping[str, str],
) -> Path:
    if tool not in {"cargo", "rustc"}:
        raise FullC6HostInputsError("Full C6 rustup tool selection is invalid")
    completed = run_build_tool(
        [os.fspath(rustup), "which", tool],
        cwd=root,
        timeout=30.0,
        env=environment,
        inherit_env=False,
        max_output_bytes=_VERSION_OUTPUT_MAX_BYTES,
    )
    lines = [
        line.strip()
        for line in (completed.stdout or "").splitlines()
        if line.strip()
    ]
    if completed.returncode != 0 or len(lines) != 1:
        raise FullC6HostInputsError(f"Full C6 rustup which {tool} failed closed")
    selected = _lexical_absolute_path(lines[0], label=f"rustup {tool}")
    observed = _lstat_selected_executable(selected, label=f"rustup {tool}")
    if stat.S_ISLNK(observed.st_mode):
        raise FullC6HostInputsError(f"Full C6 rustup which {tool} returned a symlink")
    return _resolve_executable(selected)


def _probe_version(
    path: Path,
    *,
    root: Path,
    environment: Mapping[str, str],
) -> str:
    completed = run_build_tool(
        [os.fspath(path), "--version"],
        cwd=root,
        timeout=30.0,
        env=environment,
        inherit_env=False,
        max_output_bytes=_VERSION_OUTPUT_MAX_BYTES,
    )
    output = (completed.stdout or "").strip() or (completed.stderr or "").strip()
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if completed.returncode != 0 or not lines:
        raise FullC6HostInputsError(f"Full C6 {path.name} version probe failed")
    reported = lines[0]
    if (
        len(reported) > 512
        or reported != unicodedata.normalize("NFC", reported)
        or any(ord(character) < 32 for character in reported)
    ):
        raise FullC6HostInputsError(f"Full C6 {path.name} version output is invalid")
    return reported


def _probe_rustc_host(
    path: Path,
    *,
    root: Path,
    environment: Mapping[str, str],
) -> str:
    completed = run_build_tool(
        [os.fspath(path), "-vV"],
        cwd=root,
        timeout=30.0,
        env=environment,
        inherit_env=False,
        max_output_bytes=_VERSION_OUTPUT_MAX_BYTES,
    )
    lines = [line.strip() for line in (completed.stdout or "").splitlines()]
    hosts = [line.removeprefix("host:").strip() for line in lines if line.startswith("host:")]
    if (
        completed.returncode != 0
        or len(hosts) != 1
        or not hosts[0]
        or any(ord(character) < 33 or ord(character) > 126 for character in hosts[0])
    ):
        raise FullC6HostInputsError("Full C6 rustc verbose host probe failed closed")
    return hosts[0]


def _require_version_pin(display: str, reported: str, pin: str | None) -> None:
    match = _VERSION_RE.search(reported)
    numeric = match.group(0) if match is not None else None
    if numeric is None:
        raise FullC6HostInputsError(f"Full C6 {display} version is not parseable")
    error = check_version_pin(display, [], pin, reported=numeric)
    if error is not None:
        raise FullC6HostInputsError(error)


def _capture_installed_rextio_identity() -> RextioIdentity:
    if sys.dont_write_bytecode is not True:
        raise FullC6HostInputsError(
            "installed Rextio inventory requires a cache-free Python process"
        )
    try:
        import rextio

        if type(__version__) is not str or not _installed_version_is_canonical(
            __version__
        ):
            raise FullC6HostInputsError("running Rextio version is invalid")
        module_file = _lexical_absolute_path(
            rextio.__file__ or "", label="running Rextio module"
        )
        if module_file.name != "__init__.py" or module_file.parent.name != "rextio":
            raise FullC6HostInputsError(
                "running Rextio module root is not canonical"
            )
        distribution_root = module_file.parent.parent
        _require_secure_directory(distribution_root, label="distribution root")
        dist_info = _discover_installed_rextio_dist_info(
            distribution_root, version=__version__
        )
        metadata_data, _metadata_stat = _secure_read_regular(
            dist_info / "METADATA",
            label="installed Rextio METADATA",
            max_bytes=_METADATA_MAX_BYTES,
            reject_hardlinks=True,
        )
        _validate_installed_rextio_metadata(metadata_data, version=__version__)
        direct_url_data = _secure_read_optional_regular(
            dist_info / "direct_url.json",
            label="installed Rextio direct_url metadata",
            max_bytes=_DIRECT_URL_MAX_BYTES,
        )
        _validate_installed_rextio_direct_url(direct_url_data)
        record_path = dist_info / "RECORD"
        record_data, _record_stat = _secure_read_regular(
            record_path,
            label="installed Rextio RECORD",
            max_bytes=_RECORD_MAX_BYTES,
            reject_hardlinks=True,
        )
        _validate_installed_dist_info_record(
            record_data,
            dist_info_name=dist_info.name,
            metadata_data=metadata_data,
            direct_url_data=direct_url_data,
        )
        return _capture_record_backed_rextio_identity(
            distribution_root=distribution_root,
            record_path=record_path,
            module_file=module_file,
            version=__version__,
            expected_record_sha256=hashlib.sha256(record_data).hexdigest(),
        )
    except FullC6HostInputsError:
        raise
    except Exception as exc:
        raise FullC6HostInputsError("installed Rextio inventory failed closed") from exc


def _installed_version_is_canonical(value: str) -> bool:
    return (
        value == unicodedata.normalize("NFC", value)
        and len(value.encode("utf-8")) <= 256
        and re.fullmatch(r"[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*", value)
        is not None
    )


def _installed_dist_info_name(version: str) -> str:
    normalized_version = re.sub(r"-+", "_", version).lower()
    return f"rextio-{normalized_version}.dist-info"


def _discover_installed_rextio_dist_info(
    distribution_root: Path, *, version: str
) -> Path:
    expected_name = _installed_dist_info_name(version)
    descriptor = _open_absolute_directory_no_follow(
        distribution_root, label="distribution root"
    )
    candidates: list[str] = []
    entries = 0
    try:
        with os.scandir(descriptor) as iterator:
            for item in iterator:
                entries += 1
                if entries > _DISTRIBUTION_ROOT_MAX_ENTRIES:
                    raise FullC6HostInputsError(
                        "installed Rextio distribution root exceeds its entry bound"
                    )
                name = item.name
                folded = name.casefold()
                if not (folded.startswith("rextio-") and folded.endswith(".dist-info")):
                    continue
                observed = item.stat(follow_symlinks=False)
                if (
                    name != unicodedata.normalize("NFC", name)
                    or not stat.S_ISDIR(observed.st_mode)
                    or stat.S_ISLNK(observed.st_mode)
                ):
                    raise FullC6HostInputsError(
                        "installed Rextio dist-info root is unsafe"
                    )
                candidates.append(name)
                if len(candidates) > 1:
                    raise FullC6HostInputsError(
                        "installed Rextio dist-info root is ambiguous"
                    )
    except FullC6HostInputsError:
        raise
    except OSError as exc:
        raise FullC6HostInputsError(
            "installed Rextio dist-info root discovery failed"
        ) from exc
    finally:
        os.close(descriptor)
    if candidates != [expected_name]:
        raise FullC6HostInputsError(
            "running and installed Rextio versions or roots differ"
        )
    result = distribution_root / expected_name
    _require_secure_directory(result, label="installed Rextio dist-info root")
    return result


def _validate_installed_rextio_metadata(data: bytes, *, version: str) -> None:
    try:
        message = BytesParser(policy=compat32).parsebytes(data)
        names = message.get_all("Name", [])
        versions = message.get_all("Version", [])
    except Exception as exc:
        raise FullC6HostInputsError(
            "installed Rextio METADATA is malformed"
        ) from exc
    if message.defects or message.is_multipart():
        raise FullC6HostInputsError("installed Rextio METADATA is malformed")
    if names != ["rextio"] or versions != [version]:
        raise FullC6HostInputsError(
            "installed Rextio METADATA name or version is missing or ambiguous"
        )


def _secure_read_optional_regular(
    path: Path, *, label: str, max_bytes: int
) -> bytes | None:
    parent_fd = _open_absolute_directory_no_follow(path.parent, label=f"{label} parent")
    try:
        try:
            observed = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
            raise FullC6HostInputsError(f"Full C6 {label} is not a regular file")
    except FullC6HostInputsError:
        raise
    except OSError as exc:
        raise FullC6HostInputsError(f"Full C6 {label} could not be inspected") from exc
    finally:
        os.close(parent_fd)
    data, _opened = _secure_read_regular(
        path,
        label=label,
        max_bytes=max_bytes,
        reject_hardlinks=True,
    )
    return data


def _validate_installed_rextio_direct_url(data: bytes | None) -> None:
    if data is None:
        return
    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_direct_url_object,
            parse_constant=_reject_direct_url_constant,
        )
        _validate_direct_url_shape(document)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise FullC6HostInputsError("Rextio direct_url metadata is malformed") from exc
    if not isinstance(document, dict):
        raise FullC6HostInputsError("Rextio direct_url metadata is malformed")
    directory = document.get("dir_info")
    if directory is not None and not isinstance(directory, dict):
        raise FullC6HostInputsError("Rextio direct_url metadata is malformed")
    if isinstance(directory, dict) and "editable" in directory:
        editable = directory["editable"]
        if type(editable) is not bool:
            raise FullC6HostInputsError("Rextio direct_url metadata is malformed")
        if editable:
            raise FullC6HostInputsError("editable Rextio installs are forbidden")


def _direct_url_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate direct_url JSON key")
        result[key] = value
    return result


def _reject_direct_url_constant(value: str) -> object:
    raise ValueError(f"nonstandard direct_url JSON constant: {value}")


def _validate_direct_url_shape(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _DIRECT_URL_MAX_NODES or depth > _DIRECT_URL_MAX_DEPTH:
            raise ValueError("direct_url JSON shape exceeds the bound")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def _validate_installed_dist_info_record(
    data: bytes,
    *,
    dist_info_name: str,
    metadata_data: bytes,
    direct_url_data: bytes | None,
) -> None:
    expected_payloads = {f"{dist_info_name}/METADATA": metadata_data}
    direct_url_name = f"{dist_info_name}/direct_url.json"
    if direct_url_data is not None:
        expected_payloads[direct_url_name] = direct_url_data
    record_name = f"{dist_info_name}/RECORD"
    observed_payloads: set[str] = set()
    record_rows = 0
    direct_url_rows = 0
    for row in _iter_installed_record_rows(data):
        if len(row) != 3:
            raise FullC6HostInputsError("installed Rextio RECORD row is malformed")
        raw_name, raw_hash, raw_size = row
        if raw_name == record_name:
            record_rows += 1
            if raw_hash or raw_size:
                raise FullC6HostInputsError(
                    "installed Rextio RECORD self-row is malformed"
                )
            continue
        if raw_name == direct_url_name:
            direct_url_rows += 1
        payload = expected_payloads.get(raw_name)
        if payload is None:
            continue
        if raw_name in observed_payloads:
            raise FullC6HostInputsError(
                "installed Rextio dist-info RECORD membership is ambiguous"
            )
        digest = _record_sha256(raw_hash)
        try:
            size = int(raw_size)
        except ValueError as exc:
            raise FullC6HostInputsError(
                "installed Rextio dist-info RECORD size is invalid"
            ) from exc
        if size != len(payload) or not _digest_equal(
            hashlib.sha256(payload).hexdigest(), digest
        ):
            raise FullC6HostInputsError(
                "installed Rextio dist-info differs from RECORD"
            )
        observed_payloads.add(raw_name)
    if record_rows != 1 or set(expected_payloads) != observed_payloads:
        raise FullC6HostInputsError(
            "installed Rextio dist-info RECORD membership is missing or ambiguous"
        )
    if direct_url_data is None and direct_url_rows:
        raise FullC6HostInputsError(
            "installed Rextio direct_url RECORD membership has no file"
        )


def _iter_installed_record_rows(data: bytes) -> Iterator[list[str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FullC6HostInputsError(
            "installed Rextio RECORD is not valid UTF-8 CSV"
        ) from exc
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    rows = 0
    try:
        for row in reader:
            rows += 1
            if rows > _RECORD_MAX_ROWS:
                raise FullC6HostInputsError(
                    "installed Rextio RECORD row count is outside bound"
                )
            yield row
    except csv.Error as exc:
        raise FullC6HostInputsError(
            "installed Rextio RECORD is not valid UTF-8 CSV"
        ) from exc
    if rows == 0:
        raise FullC6HostInputsError(
            "installed Rextio RECORD row count is outside bound"
        )


def _capture_record_backed_rextio_identity(
    *,
    distribution_root: Path,
    record_path: Path,
    module_file: Path,
    version: str,
    expected_record_sha256: str | None = None,
) -> RextioIdentity:
    root = _lexical_absolute_path(distribution_root, label="distribution root")
    _require_secure_directory(root, label="distribution root")
    record = _lexical_absolute_path(record_path, label="RECORD")
    try:
        record.relative_to(root)
    except ValueError as exc:
        raise FullC6HostInputsError("installed Rextio RECORD escaped distribution root") from exc
    record_data, _record_stat = _secure_read_regular(
        record,
        label="installed Rextio RECORD",
        max_bytes=_RECORD_MAX_BYTES,
        reject_hardlinks=True,
    )
    if expected_record_sha256 is not None and not _digest_equal(
        hashlib.sha256(record_data).hexdigest(), expected_record_sha256
    ):
        raise FullC6HostInputsError("installed Rextio RECORD changed during capture")

    expected: dict[str, tuple[str, int]] = {}
    aliases: set[str] = set()
    declared_bytes = 0
    for row in _iter_installed_record_rows(record_data):
        if len(row) != 3:
            raise FullC6HostInputsError("installed Rextio RECORD row is malformed")
        raw_name, raw_hash, raw_size = row
        if not raw_name.startswith("rextio/"):
            continue
        logical = _validated_record_member(raw_name)
        alias = unicodedata.normalize("NFC", logical).casefold()
        if alias in aliases:
            raise FullC6HostInputsError("installed Rextio RECORD contains a path alias")
        aliases.add(alias)
        logical_path = PurePosixPath(logical)
        if "__pycache__" in logical_path.parts or logical_path.suffix == ".pyc":
            raise FullC6HostInputsError(
                "installed Rextio RECORD contains a bytecode cache row"
            )
        digest = _record_sha256(raw_hash)
        try:
            size = int(raw_size)
        except ValueError as exc:
            raise FullC6HostInputsError("installed Rextio RECORD size is invalid") from exc
        if size < 0:
            raise FullC6HostInputsError("installed Rextio RECORD size is invalid")
        declared_bytes += size
        if declared_bytes > MAX_FULL_C6_ANALYSIS_SOURCE_BYTES:
            raise FullC6HostInputsError(
                "installed Rextio RECORD exceeds the cumulative byte bound"
            )
        expected[logical] = (digest, size)
    if not expected:
        raise FullC6HostInputsError("installed Rextio RECORD has no package inventory")

    package_root = root / "rextio"
    allowed_members = frozenset(expected)
    allowed_directories = _installed_record_directories(allowed_members)
    complete_observed = _walk_installed_package(
        package_root,
        distribution_root=root,
        allowed_members=allowed_members,
        allowed_directories=allowed_directories,
    )
    observed = complete_observed
    if set(observed) != set(expected):
        raise FullC6HostInputsError(
            "installed Rextio source is missing, outside RECORD, or unrecorded"
        )
    inode_keys: set[tuple[int, int]] = set()
    files: dict[str, Path] = {}
    for logical in sorted(expected):
        path, data, opened = observed[logical]
        digest, size = expected[logical]
        if len(data) != size or not _digest_equal(hashlib.sha256(data).hexdigest(), digest):
            raise FullC6HostInputsError("installed Rextio file differs from RECORD")
        key = (opened.st_dev, opened.st_ino)
        if opened.st_nlink != 1 or key in inode_keys:
            raise FullC6HostInputsError("installed Rextio source contains a hardlink")
        inode_keys.add(key)
        files[logical] = path
    init_path = observed.get("rextio/__init__.py")
    try:
        imported = module_file.resolve(strict=True)
    except OSError as exc:
        raise FullC6HostInputsError("running Rextio module is unavailable") from exc
    if init_path is None or imported != init_path[0]:
        raise FullC6HostInputsError("running Rextio module is not the RECORD-backed install")
    try:
        identity = capture_rextio_identity(files, version=version)
    except (BuildInputIdentityError, ToolchainIdentityError, TypeError, ValueError) as exc:
        raise FullC6HostInputsError("installed Rextio identity failed closed") from exc
    identity_by_name = {item.logical_name: item for item in identity.files}
    if set(identity_by_name) != set(expected) or any(
        identity_by_name[name].sha256 != digest
        or identity_by_name[name].size != size
        for name, (digest, size) in expected.items()
    ):
        raise FullC6HostInputsError("installed Rextio identity differs from RECORD")
    repeated = _walk_installed_package(
        package_root,
        distribution_root=root,
        allowed_members=allowed_members,
        allowed_directories=allowed_directories,
    )
    if _installed_projection(repeated) != _installed_projection(complete_observed):
        raise FullC6HostInputsError("installed Rextio source changed during identity capture")
    return identity


def _walk_installed_package(
    package_root: Path,
    *,
    distribution_root: Path,
    allowed_members: frozenset[str],
    allowed_directories: frozenset[str],
) -> dict[str, tuple[Path, bytes, os.stat_result]]:
    _require_secure_directory(package_root, label="installed Rextio package")
    pending = [package_root]
    result: dict[str, tuple[Path, bytes, os.stat_result]] = {}
    aliases: set[str] = set()
    observed_entries = 0
    observed_bytes = 0
    # One unexpected entry is enough for a precise fail-closed diagnostic;
    # a flood is stopped before any unrecorded file body is opened.
    maximum_entries = len(allowed_members) + len(allowed_directories)
    while pending:
        directory = pending.pop()
        descriptor = _open_absolute_directory_no_follow(
            directory, label="installed Rextio package"
        )
        try:
            with os.scandir(descriptor) as iterator:
                children: list[tuple[str, os.stat_result]] = []
                for item in iterator:
                    observed_entries += 1
                    if observed_entries > maximum_entries:
                        raise FullC6HostInputsError(
                            "installed Rextio package exceeds its RECORD bound"
                        )
                    children.append((item.name, item.stat(follow_symlinks=False)))
                children.sort(key=lambda item: item[0])
        except OSError as exc:
            raise FullC6HostInputsError("installed Rextio member changed") from exc
        finally:
            os.close(descriptor)
        local_aliases: set[str] = set()
        for name, observed in children:
            if name != unicodedata.normalize("NFC", name) or name in {"", ".", ".."}:
                raise FullC6HostInputsError("installed Rextio path is not canonical")
            local_alias = name.casefold()
            if local_alias in local_aliases:
                raise FullC6HostInputsError("installed Rextio package contains a path alias")
            local_aliases.add(local_alias)
            path = directory / name
            if name.casefold() == "__pycache__" or name.casefold().endswith(".pyc"):
                raise FullC6HostInputsError(
                    "installed Rextio package contains physical bytecode"
                )
            if stat.S_ISLNK(observed.st_mode):
                raise FullC6HostInputsError("installed Rextio package contains a symlink")
            if stat.S_ISDIR(observed.st_mode):
                try:
                    relative_directory = path.relative_to(distribution_root).as_posix()
                except ValueError as exc:
                    raise FullC6HostInputsError(
                        "installed Rextio directory escaped distribution root"
                    ) from exc
                if relative_directory not in allowed_directories:
                    raise FullC6HostInputsError(
                        "installed Rextio directory is outside RECORD"
                    )
                pending.append(path)
                continue
            if not stat.S_ISREG(observed.st_mode):
                raise FullC6HostInputsError("installed Rextio package contains a special file")
            try:
                relative = path.relative_to(distribution_root).as_posix()
            except ValueError as exc:
                raise FullC6HostInputsError("installed Rextio member escaped distribution root") from exc
            if relative not in allowed_members:
                raise FullC6HostInputsError(
                    "installed Rextio member is outside RECORD"
                )
            if observed.st_size > MAX_FULL_C6_ANALYSIS_SOURCE_BYTES - observed_bytes:
                raise FullC6HostInputsError(
                    "installed Rextio package exceeds the cumulative byte bound"
                )
            alias = unicodedata.normalize("NFC", relative).casefold()
            if alias in aliases:
                raise FullC6HostInputsError("installed Rextio package contains a path alias")
            aliases.add(alias)
            data, opened = _secure_read_regular(
                path,
                label="installed Rextio source",
                reject_hardlinks=True,
            )
            if len(data) > MAX_FULL_C6_ANALYSIS_SOURCE_BYTES - observed_bytes:
                raise FullC6HostInputsError(
                    "installed Rextio package exceeds the cumulative byte bound"
                )
            observed_bytes += len(data)
            result[relative] = (path, data, opened)
    return result


def _installed_record_directories(members: frozenset[str]) -> frozenset[str]:
    directories = {"rextio"}
    for member in members:
        parent = PurePosixPath(member).parent
        while parent.parts:
            directories.add(parent.as_posix())
            parent = parent.parent
    if len(directories) > _RECORD_MAX_ROWS:
        raise FullC6HostInputsError(
            "installed Rextio RECORD directory count is outside bound"
        )
    return frozenset(directories)


def _installed_projection(
    value: Mapping[str, tuple[Path, bytes, os.stat_result]],
) -> tuple[tuple[str, str, int, int, int, int], ...]:
    return tuple(
        sorted(
            (
                name,
                hashlib.sha256(data).hexdigest(),
                len(data),
                observed.st_dev,
                observed.st_ino,
                observed.st_nlink,
            )
            for name, (_path, data, observed) in value.items()
        )
    )


def _validated_record_member(value: str) -> str:
    if (
        not value
        or "\\" in value
        or "\0" in value
        or value != unicodedata.normalize("NFC", value)
    ):
        raise FullC6HostInputsError("installed Rextio RECORD path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or path.parts[0] != "rextio" or ".." in path.parts:
        raise FullC6HostInputsError("installed Rextio RECORD path escaped package root")
    if value != path.as_posix() or any(part in {"", ".", ".."} for part in path.parts):
        raise FullC6HostInputsError("installed Rextio RECORD path is not canonical")
    return path.as_posix()


def _record_sha256(value: str) -> str:
    if not value.startswith("sha256="):
        raise FullC6HostInputsError("installed Rextio RECORD lacks a SHA-256 hash")
    encoded = value.removeprefix("sha256=")
    try:
        data = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, binascii.Error) as exc:
        raise FullC6HostInputsError("installed Rextio RECORD SHA-256 is invalid") from exc
    if len(data) != 32:
        raise FullC6HostInputsError("installed Rextio RECORD SHA-256 is invalid")
    return data.hex()


def _ensure_state_directory(root: Path, config: RextioConfig) -> Path:
    request = config.build.artifact_signing_request_output
    if type(request) is not str or not request:
        raise FullC6HostInputsError("Full C6 signing-request output path is required")
    request_path = _configured_project_path(root, request)
    if request_path.name != "rextio.full-c6-final-authorization-request.json":
        raise FullC6HostInputsError("Full C6 signing-request filename is not canonical")
    state = request_path.parent
    if state == root:
        raise FullC6HostInputsError("Full C6 state directory must be below project root")
    _create_project_directory_chain(root, state, final_mode=0o700)
    observed = _require_secure_directory(state, label="state")
    if observed.uid != _current_uid() or observed.mode != 0o700:
        raise FullC6HostInputsError("Full C6 state directory must be owner-owned mode 0700")
    return state


def _ensure_publication_root(root: Path) -> Path:
    publication = root / "dist"
    _create_project_directory_chain(root, publication, final_mode=0o755)
    observed = _require_secure_directory(publication, label="publication root")
    if observed.uid != _current_uid() or observed.mode & 0o022:
        raise FullC6HostInputsError("Full C6 publication root is not owner-controlled")
    return publication


def _create_project_directory_chain(root: Path, target: Path, *, final_mode: int) -> None:
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise FullC6HostInputsError("Full C6 derived directory escaped project root") from exc
    descriptor = _open_absolute_directory_no_follow(root, label="project root")
    try:
        for index, component in enumerate(relative.parts):
            if component in {"", ".", ".."}:
                raise FullC6HostInputsError("Full C6 derived directory path is invalid")
            last = index == len(relative.parts) - 1
            mode = final_mode if last else 0o700
            try:
                before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                os.mkdir(component, mode=mode, dir_fd=descriptor)
                before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise FullC6HostInputsError("Full C6 derived path is not a real directory")
            child = os.open(component, _directory_flags(), dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                named = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                if _stat_key(before) != _stat_key(opened) or _stat_key(opened) != _stat_key(named):
                    raise FullC6HostInputsError("Full C6 derived directory changed during open")
            except Exception:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
    finally:
        os.close(descriptor)


def _create_quarantine_lease(
    project_root: Path,
) -> tuple[Path, _DirectoryBinding, Path, _DirectoryBinding, Path, _DirectoryBinding]:
    temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
    _require_secure_directory(temp_root, label="temporary root")
    container = Path(tempfile.mkdtemp(prefix="rextio-full-c6-", dir=temp_root))
    os.chmod(container, 0o700)
    container_binding = _require_secure_directory(
        container, label="quarantine container"
    )
    try:
        if container_binding.uid != _current_uid() or container_binding.mode != 0o700:
            raise FullC6HostInputsError(
                "Full C6 quarantine container must be owner-owned mode 0700"
            )
        first = container / "build-one"
        second = container / "build-two"
        first.mkdir(mode=0o700)
        second.mkdir(mode=0o700)
        first_binding = _require_private_empty_directory(
            first, label="first quarantine"
        )
        second_binding = _require_private_empty_directory(
            second, label="second quarantine"
        )
        if (
            project_root == container
            or project_root in container.parents
            or container in project_root.parents
            or first_binding.device == second_binding.device
            and first_binding.inode == second_binding.inode
        ):
            raise FullC6HostInputsError("Full C6 quarantine roots are not disjoint")
        return (
            container,
            container_binding,
            first,
            first_binding,
            second,
            second_binding,
        )
    except Exception:
        _remove_private_quarantine_container(container, container_binding)
        raise


def _remove_private_quarantine_container(
    container: Path,
    expected: _DirectoryBinding,
) -> None:
    _verify_directory_binding(container, expected, label="quarantine container")
    parent = container.parent
    parent_fd = _open_absolute_directory_no_follow(parent, label="temporary root")
    try:
        root_fd = os.open(container.name, _directory_flags(), dir_fd=parent_fd)
        try:
            opened = os.fstat(root_fd)
            if _DirectoryBinding.from_stat(opened) != expected:
                raise FullC6HostInputsError("Full C6 quarantine container changed")
            _remove_directory_contents(root_fd)
        finally:
            os.close(root_fd)
        named = os.stat(container.name, dir_fd=parent_fd, follow_symlinks=False)
        if _DirectoryBinding.from_stat(named) != expected:
            raise FullC6HostInputsError("Full C6 quarantine container name changed")
        os.rmdir(container.name, dir_fd=parent_fd)
    except FullC6HostInputsError:
        raise
    except OSError as exc:
        raise FullC6HostInputsError("Full C6 quarantine cleanup failed closed") from exc
    finally:
        os.close(parent_fd)


def _remove_directory_contents(directory_fd: int) -> None:
    with os.scandir(directory_fd) as iterator:
        names = sorted((entry.name for entry in iterator), reverse=True)
    for name in names:
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(observed.st_mode) and not stat.S_ISLNK(observed.st_mode):
            child_fd = os.open(name, _directory_flags(), dir_fd=directory_fd)
            try:
                opened = os.fstat(child_fd)
                if _stat_key(opened) != _stat_key(observed):
                    raise FullC6HostInputsError("Full C6 quarantine child changed")
                _remove_directory_contents(child_fd)
            finally:
                os.close(child_fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if _stat_key(named) != _stat_key(observed):
                raise FullC6HostInputsError("Full C6 quarantine child name changed")
            os.rmdir(name, dir_fd=directory_fd)
        else:
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if _stat_key(named) != _stat_key(observed):
                raise FullC6HostInputsError("Full C6 quarantine member changed")
            os.unlink(name, dir_fd=directory_fd)


def _require_private_empty_directory(path: Path, *, label: str) -> _DirectoryBinding:
    binding = _require_secure_directory(path, label=label)
    if binding.uid != _current_uid() or binding.mode != 0o700:
        raise FullC6HostInputsError(f"Full C6 {label} must be owner-owned mode 0700")
    descriptor = _open_absolute_directory_no_follow(path, label=label)
    try:
        with os.scandir(descriptor) as iterator:
            if next(iterator, None) is not None:
                raise FullC6HostInputsError(f"Full C6 {label} must be empty")
    finally:
        os.close(descriptor)
    return binding


def _require_secure_regular_file(path: Path, *, label: str) -> None:
    _secure_read_regular(path, label=label, reject_hardlinks=True)


def _capture_file_binding(path: Path, *, label: str) -> _FileBinding:
    data, observed = _secure_read_regular(
        path, label=label, reject_hardlinks=True
    )
    return _file_binding_from_read(data, observed)


def _file_binding_from_read(data: bytes, observed: os.stat_result) -> _FileBinding:
    """Bind bytes to the exact descriptor-stable stat returned by a secure read."""
    return _FileBinding(
        device=observed.st_dev,
        inode=observed.st_ino,
        mode=stat.S_IMODE(observed.st_mode),
        links=observed.st_nlink,
        size=observed.st_size,
        mtime_ns=getattr(
            observed, "st_mtime_ns", int(observed.st_mtime * 1_000_000_000)
        ),
        ctime_ns=getattr(
            observed, "st_ctime_ns", int(observed.st_ctime * 1_000_000_000)
        ),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _capture_namespace_directory_binding(
    path: Path,
    *,
    label: str,
) -> _NamespaceDirectoryBinding:
    descriptor = _open_absolute_directory_no_follow(path, label=label)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISDIR(observed.st_mode):
            raise FullC6HostInputsError(f"Full C6 {label} is not a directory")
        return _NamespaceDirectoryBinding.from_stat(observed)
    finally:
        os.close(descriptor)


def _verify_file_binding(path: Path, expected: _FileBinding, *, label: str) -> None:
    observed = _capture_file_binding(path, label=label)
    if observed != expected:
        raise FullC6HostInputsError(f"Full C6 {label} changed")


def _secure_read_regular(
    path: Path,
    *,
    label: str,
    max_bytes: int = 64 * 1024 * 1024,
    reject_hardlinks: bool,
) -> tuple[bytes, os.stat_result]:
    parent_fd = _open_absolute_directory_no_follow(path.parent, label=f"{label} parent")
    try:
        before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or (reject_hardlinks and before.st_nlink != 1)
            or before.st_size < 0
            or before.st_size > max_bytes
        ):
            raise FullC6HostInputsError(f"Full C6 {label} is not an unaliased regular file")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        try:
            opened = os.fstat(descriptor)
            if _regular_stat_key(opened) != _regular_stat_key(before):
                raise FullC6HostInputsError(f"Full C6 {label} changed during open")
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            final = os.fstat(descriptor)
            if (
                _regular_stat_key(final) != _regular_stat_key(opened)
                or len(data) != final.st_size
                or len(data) > max_bytes
            ):
                raise FullC6HostInputsError(f"Full C6 {label} changed during read")
        finally:
            os.close(descriptor)
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if _regular_stat_key(named) != _regular_stat_key(final):
            raise FullC6HostInputsError(f"Full C6 {label} name changed during read")
        return data, final
    except FullC6HostInputsError:
        raise
    except OSError as exc:
        raise FullC6HostInputsError(f"Full C6 {label} could not be read safely") from exc
    finally:
        os.close(parent_fd)


def _require_secure_directory(path: Path, *, label: str) -> _DirectoryBinding:
    descriptor = _open_absolute_directory_no_follow(path, label=label)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISDIR(observed.st_mode):
            raise FullC6HostInputsError(f"Full C6 {label} is not a directory")
        return _DirectoryBinding.from_stat(observed)
    finally:
        os.close(descriptor)


def _open_absolute_directory_no_follow(path: Path, *, label: str) -> int:
    lexical = _lexical_absolute_path(path, label=label)
    flags = _directory_flags()
    try:
        descriptor = os.open(os.path.sep, flags)
    except OSError as exc:
        raise FullC6HostInputsError("Full C6 filesystem root could not be opened") from exc
    try:
        for component in lexical.parts[1:]:
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise FullC6HostInputsError(f"Full C6 {label} contains a symlink")
            child = os.open(component, flags, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                named = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                if _stat_key(before) != _stat_key(opened) or _stat_key(opened) != _stat_key(named):
                    raise FullC6HostInputsError(f"Full C6 {label} changed during no-follow walk")
            except Exception:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except FullC6HostInputsError:
        os.close(descriptor)
        raise
    except OSError as exc:
        os.close(descriptor)
        raise FullC6HostInputsError(f"Full C6 {label} could not be opened safely") from exc


def _verify_directory_binding(path: Path, expected: _DirectoryBinding, *, label: str) -> None:
    observed = _directory_binding(path)
    if observed != expected:
        raise FullC6HostInputsError(f"Full C6 {label} directory changed")


def _directory_binding(path: Path) -> _DirectoryBinding:
    descriptor = _open_absolute_directory_no_follow(path, label="bound directory")
    try:
        return _DirectoryBinding.from_stat(os.fstat(descriptor))
    finally:
        os.close(descriptor)


def _directory_flags() -> int:
    required = getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
        raise FullC6HostInputsError("Full C6 no-follow directory operations are unavailable")
    return os.O_RDONLY | os.O_CLOEXEC | required


def _configured_project_path(root: Path, value: object) -> Path:
    if type(value) is not str or not value or "\\" in value or "\0" in value:
        raise FullC6HostInputsError("Full C6 configured project path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise FullC6HostInputsError("Full C6 configured project path is not canonical")
    return root.joinpath(*path.parts)


def _lexical_absolute_path(value: Path | str, *, label: str) -> Path:
    if not (type(value) is str or isinstance(value, Path)):
        raise FullC6HostInputsError(f"Full C6 {label} must be a string or Path")
    raw = os.fspath(value)
    if (
        type(raw) is not str
        or not raw
        or "\0" in raw
        or not os.path.isabs(raw)
        or os.path.abspath(raw) != raw
        or unicodedata.normalize("NFC", raw) != raw
        or (raw != os.path.sep and raw.endswith(os.path.sep))
    ):
        raise FullC6HostInputsError(
            f"Full C6 {label} must be raw lexical absolute NFC path"
        )
    return Path(raw)


def _validate_inherited_environment(
    value: Mapping[str, str] | None,
) -> dict[str, str]:
    source: Mapping[str, str] = os.environ if value is None else value
    if not isinstance(source, Mapping):
        raise FullC6HostInputsError("Full C6 inherited environment must be a mapping")
    result: dict[str, str] = {}
    for name in ("PATH", "RUSTUP_HOME"):
        item = source.get(name)
        if item is None:
            continue
        if type(item) is not str or not item or "\0" in item or len(item.encode()) > 65536:
            raise FullC6HostInputsError("Full C6 inherited environment value is invalid")
        result[name] = item
    return result


def _stat_key(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def _regular_stat_key(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)),
    )


def _current_uid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else os.getuid()


def _digest_equal(left: object, right: object) -> bool:
    if type(left) is not str or type(right) is not str:
        return False
    return len(left) == len(right) == 64 and hmac.compare_digest(left, right)


def _host_prerequisites_seal(value: FullC6HostPrerequisites) -> bytes:
    payload = {
        "domain": FULL_C6_HOST_INPUTS_DOMAIN,
        "objects": {
            "lease": id(value._lease),
            "config": id(value._config),
            "toolchain": id(value._toolchain),
            "native_tools": id(value._native_tools),
            "cargo_workspace": id(value._cargo_workspace),
            "toolchain_support_lock": id(value._toolchain_support_lock),
            "toolchain_support_plan": id(value._toolchain_support_plan),
        },
        "lease_state": {
            "active": value._lease.active,
            "generation": value._lease.generation,
            "quarantine_cleaned": value._lease.quarantine_cleaned,
            "publication_authority": (
                id(value._lease.publication_authority)
                if value._lease.publication_authority is not None
                else None
            ),
        },
        "semantics": {
            "config": hashlib.sha256(repr(value._config).encode()).hexdigest(),
            "toolchain": getattr(value._toolchain, "digest", None),
            "cargo_workspace": getattr(value._cargo_workspace, "digest", None),
            "toolchain_support_lock_raw_sha256": getattr(
                value._toolchain_support_lock,
                "raw_sha256",
                None,
            ),
            "toolchain_support_lock_merkle_sha256": getattr(
                value._toolchain_support_lock,
                "merkle_sha256",
                None,
            ),
            "toolchain_support_plan_sha256": getattr(
                value._toolchain_support_plan,
                "digest",
                None,
            ),
            "target_triple": value._target_triple,
            "source_date_epoch": FULL_C6_SOURCE_DATE_EPOCH,
            "environment": value._base_environment,
        },
        "paths": {
            name: hashlib.sha256(os.fspath(path).encode()).hexdigest()
            for name, path in (
                ("project", value._project_root),
                ("quarantine-container", value._quarantine_container),
                ("first-quarantine", value._first_quarantine_root),
                ("second-quarantine", value._second_quarantine_root),
                ("state", value._state_directory),
                ("publication", value._publication_root),
                ("toolchain-support-lock", value._toolchain_support_lock_path),
            )
        },
        "directories": {
            "project": _directory_binding_payload(value._project_binding),
            "quarantine-container": _directory_binding_payload(
                value._quarantine_container_binding
            ),
            "first-quarantine": _directory_binding_payload(
                value._first_quarantine_binding
            ),
            "second-quarantine": _directory_binding_payload(
                value._second_quarantine_binding
            ),
            "state": _directory_binding_payload(value._state_binding),
        },
        "files": {
            "toolchain-support-lock": _file_binding_payload(
                value._toolchain_support_lock_binding
            ),
        },
    }
    return hmac.new(_SEAL_KEY, _canonical_bytes(payload), hashlib.sha256).digest()


def _analysis_scope_seal(value: FullC6AnalysisScope) -> bytes:
    payload = {
        "domain": FULL_C6_ANALYSIS_SCOPE_DOMAIN,
        "objects": {
            "config": id(value._config),
            "cargo_workspace": id(value._cargo_workspace),
        },
        "semantics": {
            "config": hashlib.sha256(repr(value._config).encode()).hexdigest(),
            "cargo_workspace": getattr(value._cargo_workspace, "digest", None),
            "vendor_relative": value._vendor_relative,
            "rextioignore_policy": "strict-absent",
            "python_namespace_bounds": {
                "files": MAX_FULL_C6_ANALYSIS_PYTHON_FILES,
                "directories": MAX_FULL_C6_ANALYSIS_DIRECTORIES,
                "entries": MAX_FULL_C6_ANALYSIS_ENTRIES,
                "source_bytes": MAX_FULL_C6_ANALYSIS_SOURCE_BYTES,
                "relative_chars": MAX_FULL_C6_ANALYSIS_RELATIVE_CHARS,
                "relative_bytes": MAX_FULL_C6_ANALYSIS_RELATIVE_BYTES,
                "depth": MAX_FULL_C6_ANALYSIS_DEPTH,
            },
        },
        "paths": {
            "project": hashlib.sha256(
                os.fspath(value._project_root).encode()
            ).hexdigest(),
            "vendor": hashlib.sha256(
                os.fspath(value._vendor_root).encode()
            ).hexdigest(),
        },
        "directories": {
            "project": _directory_binding_payload(value._project_binding),
            "vendor": _directory_binding_payload(value._vendor_binding),
        },
        "python_namespace": [
            (relative, _file_binding_payload(binding))
            for relative, binding in value._python_files
        ],
        "python_directories": [
            (relative, _namespace_directory_binding_payload(binding))
            for relative, binding in value._python_directories
        ],
    }
    return hmac.new(_SEAL_KEY, _canonical_bytes(payload), hashlib.sha256).digest()


def _analysis_observation_seal(
    value: _FullC6AnalysisNamespaceObservation,
) -> bytes:
    payload = {
        "domain": f"{FULL_C6_ANALYSIS_SCOPE_DOMAIN}.observation",
        "scope": id(value._scope),
        "directories": [
            (relative, _namespace_directory_binding_payload(binding))
            for relative, binding in value._directories
        ],
    }
    return hmac.new(_SEAL_KEY, _canonical_bytes(payload), hashlib.sha256).digest()


def _publication_plan_seal(value: FullC6PublicationPlan) -> bytes:
    payload = {
        "domain": f"{FULL_C6_HOST_INPUTS_DOMAIN}.publication-plan",
        "authority": id(value._authority),
        "lease": id(value._lease),
        "lease_state": {
            "active": value._lease.active,
            "generation": value._lease.generation,
            "quarantine_cleaned": value._lease.quarantine_cleaned,
            "publication_authority": (
                id(value._lease.publication_authority)
                if value._lease.publication_authority is not None
                else None
            ),
        },
        "wheel_filename": value._wheel_filename,
        "bundle_name": value._bundle_name,
        "paths": {
            name: hashlib.sha256(os.fspath(path).encode()).hexdigest()
            for name, path in (
                ("state", value._state_directory),
                ("publication", value._publication_root),
                ("subject", value._subject_path),
                ("signature", value._final_signature_path),
                ("public-key", value._public_key_path),
            )
        },
        "directories": {
            "state": _directory_binding_payload(value._state_binding),
            "publication": _directory_binding_payload(value._publication_binding),
        },
        "files": {
            "subject": _file_binding_payload(value._subject_binding),
            "signature": _file_binding_payload(value._signature_binding),
            "public-key": _file_binding_payload(value._public_key_binding),
        },
    }
    return hmac.new(_SEAL_KEY, _canonical_bytes(payload), hashlib.sha256).digest()


def _directory_binding_payload(value: _DirectoryBinding) -> tuple[int, int, int, int]:
    return value.device, value.inode, value.uid, value.mode


def _file_binding_payload(value: _FileBinding) -> tuple[object, ...]:
    return (
        value.device,
        value.inode,
        value.mode,
        value.links,
        value.size,
        value.mtime_ns,
        value.ctime_ns,
        value.sha256,
    )


def _namespace_directory_binding_payload(
    value: _NamespaceDirectoryBinding,
) -> tuple[int, int, int, int, int, int]:
    return (
        value.device,
        value.inode,
        value.uid,
        value.mode,
        value.mtime_ns,
        value.ctime_ns,
    )


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


__all__ = [
    "FULL_C6_ANALYSIS_SCOPE_DOMAIN",
    "FULL_C6_HOST_INPUTS_DOMAIN",
    "FULL_C6_SOURCE_DATE_EPOCH",
    "MAX_FULL_C6_ANALYSIS_DEPTH",
    "MAX_FULL_C6_ANALYSIS_DIRECTORIES",
    "MAX_FULL_C6_ANALYSIS_ENTRIES",
    "MAX_FULL_C6_ANALYSIS_PYTHON_FILES",
    "MAX_FULL_C6_ANALYSIS_RELATIVE_BYTES",
    "MAX_FULL_C6_ANALYSIS_RELATIVE_CHARS",
    "MAX_FULL_C6_ANALYSIS_SOURCE_BYTES",
    "FullC6AnalysisScope",
    "FullC6HostInputsError",
    "FullC6HostPrerequisites",
    "FullC6PublicationPlan",
    "begin_full_c6_analysis_namespace",
    "collect_full_c6_analysis_scope",
    "collect_full_c6_host_prerequisites",
    "require_full_c6_analysis_files",
    "require_full_c6_analysis_scope",
    "finish_full_c6_analysis_namespace",
]
