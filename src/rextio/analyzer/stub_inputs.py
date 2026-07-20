"""Safe, deterministic snapshots of sibling ``.pyi`` inputs."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import unicodedata
from bisect import bisect_left
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from rextio.analyzer.type_collector import annotation_name, is_supported_type


class StubInputState(str, Enum):
    """Classification of a sibling stub input."""

    ABSENT = "absent"
    ABSENT_UNVERIFIED = "absent-unverified"
    PRESENT_VALID = "present-valid"
    PRESENT_UNVERIFIED = "present-unverified"
    PRESENT_INVALID = "present-invalid"


# This is deliberately an analyzer-owned version.  It describes the bytes
# projected for one stub, not the C6.13 evidence projection-set version.
STUB_SIGNATURE_PROJECTION_VERSION = 1


@dataclass(frozen=True)
class StubInputLimits:
    """Positive resource limits for one capture."""

    max_file_bytes: int = 1_048_576
    max_signatures_per_file: int = 1_000
    max_source_records: int = 10_000
    max_total_bytes: int = 16_777_216
    max_ast_nodes: int = 100_000
    max_ast_depth: int = 256
    max_identifiers_per_file: int = 10_000

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class StubInputRecord:
    """Immutable metadata and safely captured stub content."""

    source_path: str
    stub_path: str
    state: StubInputState
    eligible: bool
    reason: str | None = None
    sha256: str | None = None
    size: int | None = None
    projection_sha256: str | None = None
    exact_bytes: bytes | None = None
    text: str | None = None

    def __post_init__(self) -> None:
        if type(self.source_path) is not str or type(self.stub_path) is not str:
            raise TypeError("stub paths must be strings")
        if not _is_canonical_relative(self.source_path, ".py"):
            raise ValueError("source path must be a canonical project-relative .py path")
        if not _is_canonical_relative(self.stub_path, ".pyi"):
            raise ValueError("stub path must be a canonical project-relative .pyi path")
        if self.stub_path != self.source_path[:-3] + ".pyi":
            raise ValueError("stub path must be derived from source path")
        if type(self.state) is not StubInputState or type(self.eligible) is not bool:
            raise ValueError("invalid stub record state")
        if self.state in {StubInputState.ABSENT, StubInputState.ABSENT_UNVERIFIED}:
            if self.eligible or any(value is not None for value in (self.reason, self.sha256, self.size, self.projection_sha256, self.exact_bytes, self.text)):
                raise ValueError("absent stub records cannot contain content or metadata")
        elif self.state is StubInputState.PRESENT_VALID:
            if not self.eligible or self.reason is not None or self.sha256 is None or self.size is None or self.projection_sha256 is None or self.exact_bytes is None or self.text is None:
                raise ValueError("valid stub records require complete metadata")
        elif self.state is StubInputState.PRESENT_UNVERIFIED:
            if self.eligible or self.reason is not None or self.sha256 is None or self.size is None or self.projection_sha256 is None or self.exact_bytes is None or self.text is None:
                raise ValueError("unverified stub records require complete metadata and no eligibility")
        else:
            if self.eligible or self.reason is None:
                raise ValueError("invalid stub records require a reason and are ineligible")
        if self.reason is not None and (type(self.reason) is not str or not self.reason):
            raise ValueError("stub reason is invalid")
        if self.sha256 is not None and (type(self.sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None):
            raise ValueError("stub digest is invalid")
        if self.projection_sha256 is not None and (type(self.projection_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", self.projection_sha256) is None):
            raise ValueError("projection digest is invalid")
        if self.size is not None and (type(self.size) is not int or isinstance(self.size, bool) or self.size < 0):
            raise ValueError("stub size is invalid")
        if self.exact_bytes is not None and type(self.exact_bytes) is not bytes:
            raise TypeError("exact stub content must be bytes")
        if self.text is not None and type(self.text) is not str:
            raise TypeError("stub text must be a string")
        has_content = self.exact_bytes is not None or self.text is not None or self.sha256 is not None or self.size is not None
        if self.state is StubInputState.PRESENT_INVALID and self.projection_sha256 is not None:
            raise ValueError("invalid stub records cannot contain a projection")
        if has_content:
            if self.exact_bytes is None or self.sha256 is None or self.size is None:
                raise ValueError("stub content metadata must be complete")
            if self.sha256 != hashlib.sha256(self.exact_bytes).hexdigest() or self.size != len(self.exact_bytes):
                raise ValueError("stub content metadata does not match bytes")
            if self.text is not None and self.text.encode("utf-8") != self.exact_bytes:
                raise ValueError("stub text does not match bytes")
        if self.state is StubInputState.PRESENT_VALID:
            if self.text is None or self.exact_bytes is None or self.text.encode("utf-8") != self.exact_bytes:
                raise ValueError("valid stub text does not match bytes")

    def __repr__(self) -> str:
        return (
            "StubInputRecord("
            f"source_path={self.source_path!r}, stub_path={self.stub_path!r}, "
            f"state={self.state!r}, eligible={self.eligible!r}, reason={self.reason!r}, "
            f"sha256={self.sha256!r}, size={self.size!r}, "
            f"projection_sha256={self.projection_sha256!r})"
        )

    @property
    def analyzer_consumable(self) -> bool:
        """Whether analyzer consumers may parse the captured stub text.

        Structural stub features can be parsed for compatibility inference,
        but malformed or resource-limited inputs must not get a second parse.
        """
        return self.text is not None and (
            self.state in {StubInputState.PRESENT_VALID, StubInputState.PRESENT_UNVERIFIED}
            or self.reason in {
                "decorator",
                "duplicate-function",
                "non-stub-function-body",
                "overload-decorator",
                "unsupported-top-level",
            }
        )

    def to_dict(self) -> dict[str, Any]:
        """Return serialized metadata without raw content or root paths."""
        return {"source_path": self.source_path, "stub_path": self.stub_path, "state": self.state.value, "eligible": self.eligible, "reason": self.reason, "sha256": self.sha256, "size": self.size, "projection_sha256": self.projection_sha256}


@dataclass(frozen=True)
class StubInputSnapshot:
    """Deterministic collection of records captured for one project."""

    root: Path
    records: tuple[StubInputRecord, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.root, Path) or not self.root.is_absolute() or self.root != Path(os.path.normpath(os.fspath(self.root))):
            raise ValueError("snapshot root must be an absolute lexical path")
        if type(self.records) is not tuple or any(type(record) is not StubInputRecord for record in self.records):
            raise TypeError("snapshot records must be an exact tuple of StubInputRecord")
        paths = tuple(record.source_path for record in self.records)
        if paths != tuple(sorted(paths)):
            raise ValueError("snapshot records must be sorted and unique")
        _validate_alias_groups(paths, self.records, "source")
        stubs = tuple(record.stub_path for record in self.records)
        _validate_alias_groups(stubs, self.records, "stub")

    def for_source(self, source: Path) -> StubInputRecord:
        """Return the record for a project-relative source path."""
        source_path = _logical_path(self.root, source)
        index = bisect_left(self.records, source_path, key=lambda record: record.source_path)
        if index < len(self.records) and self.records[index].source_path == source_path:
            return self.records[index]
        raise KeyError(source)

    def to_dict(self) -> dict[str, Any]:
        """Return records without raw content or absolute paths."""
        return {"records": [record.to_dict() for record in self.records]}

    def __repr__(self) -> str:
        return f"StubInputSnapshot(records={self.records!r})"


@dataclass(frozen=True)
class _Stamp:
    device: int
    inode: int
    size: int
    ctime_ns: int
    mtime_ns: int
    mode: int
    links: int


_READ_INTERLOCK: Callable[[], None] | None = None


def capture_sibling_stub_inputs(root: Path, sources: tuple[Path, ...], *, limits: StubInputLimits | None = None) -> StubInputSnapshot:
    """Capture sibling stubs without retaining mutable filesystem state."""
    if limits is None:
        limits = StubInputLimits()
    elif type(limits) is not StubInputLimits:
        raise TypeError("stub input limits must be StubInputLimits")
    if not isinstance(root, Path) or type(sources) is not tuple or any(not isinstance(source, Path) for source in sources):
        raise TypeError("stub input capture paths must be exact Path/tuple values")
    root = Path(os.path.abspath(root))
    source_entries = [(_logical_path(root, source), Path(os.path.abspath(source))) for source in sources]
    source_entries.sort(key=lambda entry: entry[0])
    aliases: dict[str, int] = {}
    stub_aliases: dict[str, int] = {}
    for source_path, _ in source_entries:
        aliases[_alias_key(source_path)] = aliases.get(_alias_key(source_path), 0) + 1
        stub_path = source_path[:-3] + ".pyi"
        stub_aliases[_alias_key(stub_path)] = stub_aliases.get(_alias_key(stub_path), 0) + 1

    records: list[StubInputRecord] = []
    total_bytes = 0
    for index, (source_path, source) in enumerate(source_entries):
        stub_path = _logical_path(root, source.with_suffix(".pyi"))
        if aliases[_alias_key(source_path)] > 1 or stub_aliases[_alias_key(stub_path)] > 1:
            record = _invalid(source_path, stub_path, "logical-path-alias")
        elif index >= limits.max_source_records:
            record = _invalid(source_path, stub_path, "source-record-limit")
        else:
            record, consumed = _capture_one(root, source_path, stub_path, limits, total_bytes)
            total_bytes += consumed
        records.append(record)
    return StubInputSnapshot(root=root, records=tuple(records))


def _capture_one(root: Path, source_path: str, stub_path: str, limits: StubInputLimits, total_bytes: int) -> tuple[StubInputRecord, int]:
    result = _read_secure_stub(root, stub_path, limits.max_file_bytes)
    compatibility_reader = False
    if result == ("invalid", "secure-read-unavailable"):
        compatibility_reader = True
        result = _read_compatibility_stub(root, stub_path, limits.max_file_bytes)
    if result[0] == "absent":
        state = StubInputState.ABSENT_UNVERIFIED if compatibility_reader else StubInputState.ABSENT
        return StubInputRecord(source_path, stub_path, state, False), 0
    if result[0] not in {"ok", "unverified"}:
        reason = result[1]
        if not isinstance(reason, str):
            raise ValueError("secure stub reader returned invalid failure reason")
        return _invalid(source_path, stub_path, reason), 0
    payload = result[1]
    if not isinstance(payload, bytes):
        raise ValueError("secure stub reader returned invalid payload")
    if total_bytes + len(payload) > limits.max_total_bytes:
        return _invalid(source_path, stub_path, "total-bytes-limit"), 0
    digest = hashlib.sha256(payload).hexdigest()
    verified = result[0] == "ok"
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return StubInputRecord(source_path, stub_path, StubInputState.PRESENT_INVALID, False, "invalid-utf8", digest, len(payload), exact_bytes=payload), len(payload)
    try:
        tree = ast.parse(text, filename=stub_path)
    except (SyntaxError,):
        return StubInputRecord(source_path, stub_path, StubInputState.PRESENT_INVALID, False, "invalid-syntax", digest, len(payload), exact_bytes=payload, text=text), len(payload)
    except RecursionError:
        return StubInputRecord(source_path, stub_path, StubInputState.PRESENT_INVALID, False, "parser-recursion", digest, len(payload), exact_bytes=payload, text=text), len(payload)
    except MemoryError:
        return StubInputRecord(source_path, stub_path, StubInputState.PRESENT_INVALID, False, "parser-memory", digest, len(payload), exact_bytes=payload, text=text), len(payload)
    stub_reason = _stub_reason(tree, limits)
    if stub_reason is not None:
        return StubInputRecord(source_path, stub_path, StubInputState.PRESENT_INVALID, False, stub_reason, digest, len(payload), exact_bytes=payload, text=text), len(payload)
    try:
        projection = _projection_digest(tree)
    except RecursionError:
        return StubInputRecord(source_path, stub_path, StubInputState.PRESENT_INVALID, False, "projection-recursion", digest, len(payload), exact_bytes=payload, text=text), len(payload)
    except MemoryError:
        return StubInputRecord(source_path, stub_path, StubInputState.PRESENT_INVALID, False, "projection-memory", digest, len(payload), exact_bytes=payload, text=text), len(payload)
    state = StubInputState.PRESENT_VALID if verified else StubInputState.PRESENT_UNVERIFIED
    return StubInputRecord(source_path, stub_path, state, verified, sha256=digest, size=len(payload), projection_sha256=projection, exact_bytes=payload, text=text), len(payload)


def _read_secure_stub(root: Path, logical_stub: str, max_bytes: int) -> tuple[str, bytes | str]:
    if not _secure_api_available():
        return "invalid", "secure-read-unavailable"
    parts = logical_stub.split("/")
    dirs: list[tuple[int, int | None, str | None, _Stamp]] = []
    fd = -1
    try:
        dirs = _open_directory_chain(root, parts[:-1])
        parent = dirs[-1][0]
        name = parts[-1]
        try:
            before = _stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))
        except FileNotFoundError:
            _verify_chain(dirs)
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                _verify_chain(dirs)
                return "absent", ""
            return "invalid", "secure-read-race"
        if stat.S_ISLNK(before.mode):
            return "invalid", "unsafe-symlink"
        if not stat.S_ISREG(before.mode):
            return "invalid", "unsafe-file-type"
        if before.links != 1:
            return "invalid", "unsafe-link-count"
        if before.size > max_bytes:
            return "invalid", "file-bytes-limit"
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(name, flags, dir_fd=parent)
        opened = _stamp(os.fstat(fd))
        if opened != before or opened.links != 1 or not stat.S_ISREG(opened.mode):
            return "invalid", "secure-read-race"
        chunks: list[bytes] = []
        total_read = 0
        while total_read <= max_bytes:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total_read))
            if not chunk:
                break
            chunks.append(chunk)
            total_read += len(chunk)
        payload = b"".join(chunks)
        if len(payload) != opened.size or len(payload) > max_bytes:
            return "invalid", "file-bytes-limit" if len(payload) > max_bytes else "secure-read-race"
        if _READ_INTERLOCK is not None:
            _READ_INTERLOCK()
        after = _stamp(os.fstat(fd))
        linked = _stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))
        _verify_chain(dirs)
        if after != opened or linked != opened:
            return "invalid", "secure-read-race"
        return "ok", payload
    except (AttributeError, NotImplementedError, OSError) as exc:
        if fd >= 0:
            return "invalid", "secure-read-race"
        if isinstance(exc, OSError) and exc.errno in {getattr(os, "ENOTSUP", -1), getattr(os, "EOPNOTSUPP", -1)}:
            return "invalid", "secure-read-unavailable"
        return "invalid", "secure-read-failed"
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        for handle, _, _, _ in reversed(dirs):
            try:
                os.close(handle)
            except OSError:
                pass


def _read_compatibility_stub(root: Path, logical_stub: str, max_bytes: int) -> tuple[str, bytes | str]:
    """Read a sibling stub when descriptor-relative APIs are unavailable.

    This path is intentionally unverified: it snapshots bytes for analyzer
    compatibility, but its result is never eligible for C6.13 evidence.
    """
    root = Path(os.path.abspath(root))
    path = root.joinpath(*logical_stub.split("/"))
    try:
        relative = path.relative_to(root)
    except ValueError:
        return "invalid", "path-outside-root"
    current = root
    try:
        for part in relative.parts[:-1]:
            current /= part
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode):
                return "invalid", "unsafe-symlink"
            if not stat.S_ISDIR(info.st_mode):
                return "invalid", "unsafe-file-type"
        info = os.lstat(path)
    except FileNotFoundError:
        return "absent", ""
    except OSError:
        return "invalid", "compatibility-read-failed"
    if stat.S_ISLNK(info.st_mode):
        return "invalid", "unsafe-symlink"
    if not stat.S_ISREG(info.st_mode):
        return "invalid", "unsafe-file-type"
    if info.st_nlink != 1:
        return "invalid", "unsafe-link-count"
    if info.st_size > max_bytes:
        return "invalid", "file-bytes-limit"
    before = _stamp(info)
    try:
        with path.open("rb") as handle:
            opened = _stamp(os.fstat(handle.fileno()))
            if opened != before or opened.links != 1 or not stat.S_ISREG(opened.mode):
                return "invalid", "compatibility-read-race"
            payload = handle.read(max_bytes + 1)
            if _READ_INTERLOCK is not None:
                _READ_INTERLOCK()
            after = _stamp(os.fstat(handle.fileno()))
    except (OSError, ValueError):
        return "invalid", "compatibility-read-failed"
    if len(payload) > max_bytes:
        return "invalid", "file-bytes-limit"
    try:
        linked = _stamp(os.lstat(path))
    except (FileNotFoundError, OSError):
        return "invalid", "compatibility-read-race"
    if after != opened or linked != opened or stat.S_ISLNK(linked.mode) or not stat.S_ISREG(linked.mode):
        return "invalid", "compatibility-read-race"
    return "unverified", payload


def _secure_api_available() -> bool:
    try:
        return (
            all(hasattr(os, name) for name in ("open", "fstat", "stat", "read", "O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"))
            and os.open in os.supports_dir_fd
            and os.stat in os.supports_dir_fd
            and os.stat in os.supports_follow_symlinks
        )
    except (AttributeError, TypeError):
        return False


def _stamp(value: os.stat_result) -> _Stamp:
    return _Stamp(value.st_dev, value.st_ino, value.st_size, value.st_ctime_ns, value.st_mtime_ns, value.st_mode, value.st_nlink)


def _open_directory_chain(root: Path, parts: list[str]) -> list[tuple[int, int | None, str | None, _Stamp]]:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    handles: list[tuple[int, int | None, str | None, _Stamp]] = []
    current = -1
    try:
        current = os.open(Path(os.path.abspath(root)).anchor, flags)
        root_stamp = _stamp(os.fstat(current))
        handles.append((current, None, None, root_stamp))
        for part in Path(os.path.abspath(root)).parts[1:] + tuple(parts):
            if not part or part in {".", ".."} or "/" in part or "\\" in part:
                raise OSError("unsafe path component")
            nxt = -1
            try:
                nxt = os.open(part, flags, dir_fd=current)
                expected = _stamp(os.fstat(nxt))
                linked = _stamp(os.stat(part, dir_fd=current, follow_symlinks=False))
                if expected != linked or not stat.S_ISDIR(expected.mode):
                    raise OSError("directory changed")
                handles.append((nxt, current, part, expected))
                current = nxt
                nxt = -1
            finally:
                if nxt >= 0:
                    try:
                        os.close(nxt)
                    except OSError:
                        pass
        return handles
    except BaseException:
        if current >= 0 and not handles:
            try:
                os.close(current)
            except OSError:
                pass
        for handle, _, _, _ in reversed(handles):
            try:
                os.close(handle)
            except OSError:
                pass
        raise


def _verify_chain(handles: list[tuple[int, int | None, str | None, _Stamp]]) -> None:
    for handle, parent, name, expected in handles:
        if _stamp(os.fstat(handle)) != expected:
            raise OSError("directory changed")
        if parent is not None and name is not None and _stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected:
            raise OSError("directory link changed")


def _stub_reason(tree: ast.Module, limits: StubInputLimits) -> str | None:
    nodes, depth, identifiers = _ast_stats(tree, limits)
    if nodes > limits.max_ast_nodes:
        return "ast-node-limit"
    if depth > limits.max_ast_depth:
        return "ast-depth-limit"
    if identifiers > limits.max_identifiers_per_file:
        return "identifier-count-limit"
    functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if len(functions) > limits.max_signatures_per_file:
        return "signature-count-limit"
    names: set[str] = set()
    for node in functions:
        if node.name in names:
            return "duplicate-function"
        names.add(node.name)
        if node.decorator_list:
            if any(_decorator_name(decorator) == "overload" for decorator in node.decorator_list):
                return "overload-decorator"
            return "decorator"
        if len(node.body) != 1 or not (isinstance(node.body[0], ast.Pass) or (isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and node.body[0].value.value is Ellipsis)):
            return "non-stub-function-body"
    allowed = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Import, ast.ImportFrom)
    if any(not isinstance(node, allowed) for node in tree.body):
        return "unsupported-top-level"
    return None


def _ast_stats(node: ast.AST, limits: StubInputLimits) -> tuple[int, int, int]:
    count = depth = identifiers = 0
    stack = [(node, 1)]
    while stack:
        current, current_depth = stack.pop()
        count += 1
        depth = max(depth, current_depth)
        identifiers += isinstance(current, ast.Name)
        if count > limits.max_ast_nodes or depth > limits.max_ast_depth or identifiers > limits.max_identifiers_per_file:
            break
        stack.extend((child, current_depth + 1) for child in ast.iter_child_nodes(current))
    return count, depth, identifiers


def _projection_digest(tree: ast.Module) -> str:
    projection = {
        "version": STUB_SIGNATURE_PROJECTION_VERSION,
        "functions": [
            {
                "name": node.name,
                "async": isinstance(node, ast.AsyncFunctionDef),
                "arguments": [
                    {"name": arg.arg, "annotation": _projection_annotation(arg.annotation)}
                    for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
                ],
                "return": _projection_annotation(node.returns),
            }
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ],
    }
    encoded = json.dumps(projection, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _projection_annotation(node: ast.AST | None) -> str:
    """Normalize only supported annotations; never unparse arbitrary AST."""
    if node is None or not is_supported_type(node):
        return "<unsupported>"
    return annotation_name(node)


def _decorator_name(node: ast.expr) -> str | None:
    return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None


def _alias_key(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _is_canonical_relative(path: str, suffix: str) -> bool:
    return (
        path == Path(path).as_posix()
        and not Path(path).is_absolute()
        and "\\" not in path
        and all(part not in {"", ".", ".."} for part in path.split("/"))
        and path.endswith(suffix)
    )


def _logical_path(root: Path, path: Path) -> str:
    absolute_root = Path(os.path.abspath(root))
    absolute_path = Path(os.path.abspath(path))
    try:
        return absolute_path.relative_to(absolute_root).as_posix()
    except ValueError as exc:
        raise KeyError(path) from exc


def _invalid(source_path: str, stub_path: str, reason: str) -> StubInputRecord:
    return StubInputRecord(source_path, stub_path, StubInputState.PRESENT_INVALID, False, reason)


def _validate_alias_groups(
    paths: tuple[str, ...], records: tuple[StubInputRecord, ...], kind: str
) -> None:
    groups: dict[str, list[StubInputRecord]] = {}
    for path, record in zip(paths, records):
        groups.setdefault(_alias_key(path), []).append(record)
    for group in groups.values():
        if len(group) > 1 and not all(record.reason == "logical-path-alias" for record in group):
            raise ValueError(f"snapshot {kind} identities must be unique")
