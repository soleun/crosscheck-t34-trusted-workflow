#!/usr/bin/env python3
"""RND-4084 [spec/559-rnd-4043 T322] — merchant-app preparation helper.

Runs inside the merchant repo's trusted reusable workflow
(`templates/shopify-merchant-app/prepare.yml`). Stdlib only.

Subcommands: source-manifest, policy-check, output-manifest, stage-dist,
assemble, claim-request, claim-gate, receipt, receipt-gate. Exit 0 on success, 1 on
refusal (JSON ``{code, detail}`` on stderr), 2 on usage error. Stdout
carries only the successful output document; refusals never touch stdout
so a ``> file`` redirect cannot swallow the refusal code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tomllib
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

GIT_TIMEOUT_S = 60
MAX_SUBPROCESS_BYTES = 1 << 20  # 1 MiB cap on any git child output kept in memory
MAX_JSON_BYTES = 8 << 20  # 8 MiB cap on any manifest/claim/response input
MAX_SOURCE_FILE_BYTES = 32 << 20  # 32 MiB per source blob
MAX_BUILD_FILE_BYTES = 32 << 20  # 32 MiB per build output file
MAX_BUILD_TOTAL_BYTES = 512 << 20  # 512 MiB total build output

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_GID_RE = re.compile(r"^gid://shopify/Version/[0-9]+$")
LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1\n"
SECRET_KEY_RE = re.compile(r"token|secret|ciphertext|password|private[_-]?key|auth", re.IGNORECASE)

# T34a AppBuildReceiptV1 keys, in contract order. The receipt carries
# exactly these keys — no more, no fewer.
RECEIPT_KEYS = [
    "workspaceId",
    "deployRunId",
    "appBindingId",
    "generation",
    "repositoryId",
    "commitSha",
    "configName",
    "clientId",
    "sourceArchiveDigest",
    "buildOutputDigest",
    "tomlDigestsBefore",
    "tomlDigestsAfter",
    "extensionInventoryBefore",
    "extensionInventoryAfter",
    "trustedWorkflowRef",
    "trustedWorkflowSha",
    "githubRunId",
    "githubRunAttempt",
    "githubArtifactId",
    "githubArtifactDigest",
    "imageDigest",
    "toolchainDigest",
    "cliVersion",
    "buildStatus",
    "uploadStatus",
    "observedCandidateVersionTag",
    "observedCandidateVersionId",
]


class Refusal(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def emit_refusal(code: str, detail: str) -> int:
    print(json.dumps({"code": code, "detail": detail}), file=sys.stderr)
    return 1


def canonical_json(value: object) -> bytes:
    """Canonical JSON matching T34a's ``canonicalizeForHash``.

    JS ``JSON.stringify`` on a key-sorted structure: no whitespace, raw
    UTF-8, arrays in order. ``sort_keys`` sorts recursively, which is the
    same recursion ``canonicalizeValue`` performs.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bounded(path: str, limit: int = MAX_JSON_BYTES) -> bytes:
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise Refusal("INPUT_TOO_LARGE", f"{path} exceeds {limit} bytes")
    return data


def load_json(path: str, limit: int = MAX_JSON_BYTES) -> object:
    try:
        raw = read_bounded(path, limit)
    except FileNotFoundError:
        raise Refusal("INPUT_NOT_FOUND", f"{path} does not exist")
    except OSError as exc:
        raise Refusal("INPUT_UNREADABLE", f"{path} cannot be read: {exc}")
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise Refusal("INPUT_MALFORMED", f"{path} is not valid JSON")


def run_git(repo: str, args: list[str], input_bytes: bytes | None = None) -> bytes:
    try:
        proc = subprocess.run(
            ["git", "-C", repo, *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as exc:
        raise Refusal("GIT_TIMEOUT", f"git {' '.join(args)} timed out: {exc}")
    except OSError as exc:
        raise Refusal("GIT_UNAVAILABLE", f"cannot run git: {exc}")
    if proc.returncode != 0:
        raise Refusal("GIT_FAILED", f"git {' '.join(args)} failed: {proc.stderr[:500]!r}")
    out = proc.stdout
    if len(out) > MAX_SUBPROCESS_BYTES and args[:1] != ["cat-file"]:
        raise Refusal("GIT_OUTPUT_TOO_LARGE", f"git {' '.join(args)} output exceeds the bound")
    return out


def is_safe_app_root(value: str) -> bool:
    if not value or len(value) > 256 or value.startswith("/") or value.startswith("\\"):
        return False
    return all(seg not in ("", ".", "..") for seg in value.split("/"))


def under_root(path: str, root: str) -> str | None:
    """Return the app-root-relative path, or None when outside the root."""
    if root == ".":
        rel = path
    elif path == root:
        return ""
    elif path.startswith(root + "/"):
        rel = path[len(root) + 1 :]
    else:
        return None
    if not rel or rel.startswith("/") or "\\" in rel:
        return None
    if any(seg in ("", ".", "..") for seg in rel.split("/")):
        return None
    return rel


# ---------------------------------------------------------------------------
# source-manifest
# ---------------------------------------------------------------------------


def parse_ls_tree(raw: bytes) -> list[tuple[str, str, str, str]]:
    """Parse ``git ls-tree -r -z`` output into (mode, type, sha, path) tuples."""
    entries: list[tuple[str, str, str, str]] = []
    for chunk in raw.split(b"\0"):
        if not chunk:
            continue
        try:
            meta, path_bytes = chunk.split(b"\t", 1)
            mode, objtype, sha = meta.decode("utf-8").split(" ")
            path = path_bytes.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise Refusal("UNSAFE_PATH", "ls-tree entry is not decodable")
        entries.append((mode, objtype, sha, path))
    return entries


def blob_bytes(repo: str, sha: str, size: int, path: str) -> bytes:
    if size > MAX_SOURCE_FILE_BYTES:
        raise Refusal("FILE_TOO_LARGE", f"{path} exceeds {MAX_SOURCE_FILE_BYTES} bytes")
    out = run_git(repo, ["cat-file", "-p", sha])
    if len(out) > MAX_SUBPROCESS_BYTES and len(out) != size:
        raise Refusal("GIT_OUTPUT_TOO_LARGE", f"blob for {path} exceeds the bound")
    return out


def extract_inventory(
    toml_rel: str, toml_bytes: bytes, get_blob: Callable[[str], bytes | None]
) -> tuple[list[dict[str, str]], dict[str, str]]:
    """Parse one TOML file's extension inventory.

    Returns (records, input_query_digests). Files without an
    ``[[extensions]]`` table contribute nothing.
    """
    try:
        doc = tomllib.loads(toml_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise Refusal("TOML_UNPARSEABLE", f"{toml_rel} is not valid TOML")
    extensions = doc.get("extensions")
    if extensions is None:
        return [], {}
    if not isinstance(extensions, list):
        raise Refusal("TOML_UNPARSEABLE", f"{toml_rel}: extensions must be an array of tables")
    toml_dir = str(PurePosixPath(toml_rel).parent)
    records: list[dict[str, str]] = []
    queries: dict[str, str] = {}
    ext_dir = toml_dir if toml_dir != "." else ""
    for entry in extensions:
        if not isinstance(entry, dict):
            raise Refusal("TOML_UNPARSEABLE", f"{toml_rel}: extension entry must be a table")
        handle = entry.get("handle") or entry.get("name") or entry.get("uid") or ""
        ext_type = entry.get("type") or ""
        uid = entry.get("uid") or ""
        if not isinstance(handle, str) or not handle:
            raise Refusal("EXTENSION_IDENTITY_MISSING", f"{toml_rel}: extension needs handle, name or uid")
        identifier = handle if isinstance(handle, str) else str(handle)
        targeting = entry.get("targeting") or []
        if not isinstance(targeting, list):
            raise Refusal("TOML_UNPARSEABLE", f"{toml_rel}: targeting must be an array of tables")
        targets = [t for t in targeting if isinstance(t, dict)]
        if not targets:
            targets = [{}]
        for tgt in targets:
            target = tgt.get("target") or ""
            if not isinstance(target, str):
                raise Refusal("TOML_UNPARSEABLE", f"{toml_rel}: targeting.target must be a string")
            if not target:
                # An extension with no targeting table is inventoried under
                # its own type (e.g. a config-only function). An extension
                # with neither a target nor a type is unidentifiable.
                if not isinstance(ext_type, str) or not ext_type:
                    raise Refusal(
                        "EXTENSION_IDENTITY_MISSING",
                        f"{toml_rel}: extension {identifier} has neither targeting nor type",
                    )
                target = ext_type
            records.append(
                {
                    "identifier": identifier,
                    "type": ext_type if isinstance(ext_type, str) else "",
                    "target": target,
                    "path": ext_dir,
                    "uid": uid if isinstance(uid, str) else "",
                }
            )
            for key in ("input", "input_query", "query"):
                candidate = tgt.get(key)
                if isinstance(candidate, str) and candidate.endswith(".graphql"):
                    query_rel = str(PurePosixPath(toml_dir) / candidate) if toml_dir != "." else candidate
                    query_bytes = get_blob(query_rel)
                    if query_bytes is None:
                        raise Refusal("INPUT_QUERY_MISSING", f"{toml_rel}: {candidate} is not in the source tree")
                    queries[query_rel] = sha256_hex(query_bytes)
    return records, queries


def cmd_source_manifest(args: argparse.Namespace) -> int:
    repo = args.repo
    commit = args.commit
    app_root = args.app_root
    config_name = args.config_name
    if not FULL_SHA_RE.match(commit or ""):
        raise Refusal("COMMIT_MISMATCH", "commit must be a full 40-hex SHA")
    if not is_safe_app_root(app_root or ""):
        raise Refusal("UNSAFE_PATH", "app-root must be a safe relative path")
    if not config_name or len(config_name) > 128:
        raise Refusal("CONFIG_MISMATCH", "config-name is required (1..128 chars)")

    head = run_git(repo, ["rev-parse", "HEAD"]).decode("utf-8").strip()
    if head != commit:
        raise Refusal("COMMIT_MISMATCH", f"HEAD {head} does not equal {commit}")
    tree_sha = run_git(repo, ["rev-parse", f"{commit}^{{tree}}"]).decode("utf-8").strip()
    raw = run_git(repo, ["ls-tree", "-r", "-z", "--full-tree", commit])
    entries = parse_ls_tree(raw)

    # First pass: refuse submodules, symlinks and escaping paths.
    scoped: list[tuple[str, str, str, int, str]] = []
    for mode, objtype, sha, path in entries:
        rel = under_root(path, app_root)
        if rel is None:
            continue
        if rel == "":
            raise Refusal("UNSAFE_PATH", "the app root itself must be a directory")
        if mode == "160000":
            raise Refusal("SUBMODULE_PRESENT", f"{path} is a submodule")
        if mode == "120000":
            raise Refusal("SYMLINK_PRESENT", f"{path} is a symlink")
        if objtype != "blob":
            raise Refusal("UNSAFE_PATH", f"{path} is not a blob ({objtype})")
        try:
            size = int(run_git(repo, ["cat-file", "-s", sha]).decode("utf-8").strip())
        except ValueError:
            raise Refusal("GIT_FAILED", f"cannot size blob for {path}")
        scoped.append((rel, mode, sha, size, path))

    blobs: dict[str, bytes] = {}
    records: list[dict[str, object]] = []
    for rel, mode, sha, size, _path in scoped:
        data = blob_bytes(repo, sha, size, rel)
        if size <= 1024 and data.startswith(LFS_POINTER_PREFIX):
            raise Refusal("LFS_POINTER_PRESENT", f"{rel} is a Git-LFS pointer")
        blobs[rel] = data
        records.append({"path": rel, "mode": mode, "size": size, "sha256": sha256_hex(data)})
    records.sort(key=lambda r: str(r["path"]))

    # The worktree check runs after the commit-content refusals: every byte
    # above is read by commit/blob SHA, never from the worktree, and a
    # committed submodule otherwise always looks dirty when the caller
    # checks out with `submodules: false`.
    if run_git(repo, ["status", "--porcelain"]).strip():
        raise Refusal("DIRTY_WORKTREE", "the checkout is not clean")

    def get_blob(rel: str) -> bytes | None:
        return blobs.get(rel)

    toml_digests: dict[str, str] = {}
    inventory: list[dict[str, str]] = []
    input_queries: dict[str, str] = {}
    for record in records:
        rel = str(record["path"])
        if not rel.endswith(".toml"):
            continue
        data = blobs[rel]
        toml_digests[rel] = sha256_hex(data)
        recs, queries = extract_inventory(rel, data, get_blob)
        inventory.extend(recs)
        input_queries.update(queries)
    inventory.sort(key=lambda r: (r["identifier"], r["target"], r["path"]))

    app_toml_rel = f"shopify.app.{config_name}.toml"
    app_toml_bytes = blobs.get(app_toml_rel)
    if app_toml_bytes is None:
        raise Refusal("CONFIG_MISMATCH", f"{app_toml_rel} is not in the source tree")
    try:
        app_doc = tomllib.loads(app_toml_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise Refusal("TOML_UNPARSEABLE", f"{app_toml_rel} is not valid TOML")
    client_id = app_doc.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        raise Refusal("CLIENT_ID_MISSING", f"{app_toml_rel} has no client_id")

    manifest = {
        "commit": commit,
        "treeSha": tree_sha,
        "appRoot": app_root,
        "configName": config_name,
        "clientId": client_id,
        "records": records,
        "sourceArchiveDigest": sha256_hex(canonical_json(records)),
        "tomlDigests": dict(sorted(toml_digests.items())),
        "extensionInventory": [
            {k: r[k] for k in ("identifier", "type", "target", "path")} for r in inventory
        ],
        "inputQueryDigests": dict(sorted(input_queries.items())),
    }
    print(canonical_json(manifest).decode("utf-8"))
    return 0


# ---------------------------------------------------------------------------
# policy-check
# ---------------------------------------------------------------------------


def require_manifest_shape(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise Refusal("MANIFEST_INVALID" if name == "manifest" else "BASELINE_INVALID",
                      f"{name} must be a JSON object")
    for key in ("configName", "clientId", "tomlDigests", "extensionInventory", "inputQueryDigests"):
        if key not in value:
            raise Refusal("MANIFEST_INVALID" if name == "manifest" else "BASELINE_INVALID",
                          f"{name} is missing {key}")
    if not isinstance(value["tomlDigests"], dict) or not isinstance(value["inputQueryDigests"], dict):
        raise Refusal("MANIFEST_INVALID" if name == "manifest" else "BASELINE_INVALID",
                      f"{name} digests must be objects")
    if not isinstance(value["extensionInventory"], list):
        raise Refusal("MANIFEST_INVALID" if name == "manifest" else "BASELINE_INVALID",
                      f"{name} extensionInventory must be an array")
    return value


def cmd_policy_check(args: argparse.Namespace) -> int:
    baseline = require_manifest_shape(load_json(args.baseline), "baseline")
    manifest = require_manifest_shape(load_json(args.manifest), "manifest")
    expected_client = args.client_id

    if manifest.get("configName") != baseline.get("configName"):
        raise Refusal("CONFIG_MISMATCH",
                      f"config {manifest.get('configName')!r} != baseline {baseline.get('configName')!r}")
    for side, doc in (("manifest", manifest), ("baseline", baseline)):
        if doc.get("clientId") != expected_client:
            raise Refusal("CLIENT_ID_MISMATCH", f"{side} client_id does not equal the expected value")

    base_toml = baseline["tomlDigests"]
    cur_toml = manifest["tomlDigests"]
    assert isinstance(base_toml, dict) and isinstance(cur_toml, dict)
    for path in sorted(set(base_toml) - set(cur_toml)):
        raise Refusal("TOML_REMOVED", f"{path} was removed")
    for path in sorted(set(cur_toml) - set(base_toml)):
        raise Refusal("TOML_ADDED", f"{path} was added")
    for path in sorted(set(base_toml)):
        if base_toml[path] != cur_toml[path]:
            raise Refusal("TOML_CHANGED", f"{path} digest differs")

    def keyed(entries: object) -> dict[str, dict[str, object]]:
        assert isinstance(entries, list)
        out: dict[str, dict[str, object]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise Refusal("MANIFEST_INVALID", "inventory entry must be an object")
            ident = entry.get("identifier")
            if not isinstance(ident, str) or not ident:
                raise Refusal("MANIFEST_INVALID", "inventory entry needs an identifier")
            out.setdefault(str(ident), {})
            record_key = json.dumps(entry, sort_keys=True)
            out[str(ident)][record_key] = entry
        return out

    base_inv = keyed(baseline["extensionInventory"])
    cur_inv = keyed(manifest["extensionInventory"])
    for ident in sorted(set(base_inv) - set(cur_inv)):
        raise Refusal("EXTENSION_REMOVED", f"extension {ident} was removed")
    for ident in sorted(set(cur_inv) - set(base_inv)):
        raise Refusal("EXTENSION_ADDED", f"extension {ident} was added")
    for ident in sorted(set(base_inv)):
        if set(base_inv[ident]) != set(cur_inv[ident]):
            raise Refusal("EXTENSION_RETARGETED", f"extension {ident} inventory differs")

    base_q = baseline["inputQueryDigests"]
    cur_q = manifest["inputQueryDigests"]
    assert isinstance(base_q, dict) and isinstance(cur_q, dict)
    if dict(base_q) != dict(cur_q):
        raise Refusal("INPUT_QUERY_CHANGED", "input query set or digests differ")

    print(json.dumps({"ok": True}))
    return 0


# ---------------------------------------------------------------------------
# output-manifest
# ---------------------------------------------------------------------------


def dist_prefixes(baseline: dict[str, object]) -> list[str]:
    """Enrolled ``<extension-path>/dist/`` prefixes from the baseline inventory."""
    inventory = baseline["extensionInventory"]
    assert isinstance(inventory, list)
    return sorted({
        f"{e['path']}/dist/"
        for e in inventory
        if isinstance(e, dict) and isinstance(e.get("path"), str) and e["path"]
    })


def copy_regular_file(src: Path, rel: str, dest_dir: Path) -> int:
    """Copy one lstat-verified regular file under dest_dir/rel. Returns size."""
    try:
        st = os.lstat(src)
    except OSError:
        raise Refusal("NOT_REGULAR_FILE", f"{rel} cannot be stated")
    if not stat.S_ISREG(st.st_mode):
        raise Refusal("NOT_REGULAR_FILE", f"{rel} is not a regular file")
    if st.st_size > MAX_BUILD_FILE_BYTES:
        raise Refusal("FILE_TOO_LARGE", f"{rel} exceeds {MAX_BUILD_FILE_BYTES} bytes")
    with open(src, "rb") as fh:
        data = fh.read()
    dest = dest_dir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(data)
    return st.st_size


def cmd_output_manifest(args: argparse.Namespace) -> int:
    build_dir = Path(args.build_dir)
    if not build_dir.is_dir():
        raise Refusal("BUILD_DIR_INVALID", f"{args.build_dir} is not a directory")
    baseline = require_manifest_shape(load_json(args.baseline), "baseline")
    assert isinstance(baseline["tomlDigests"], dict)
    assert isinstance(baseline["extensionInventory"], list)

    dist_only = bool(args.dist_only)
    prefixes = dist_prefixes(baseline)
    base_records = baseline.get("records")
    record_digests: dict[str, str] = {}
    if isinstance(base_records, list):
        for entry in base_records:
            if (
                isinstance(entry, dict)
                and isinstance(entry.get("path"), str)
                and isinstance(entry.get("sha256"), str)
            ):
                record_digests[str(entry["path"])] = str(entry["sha256"])

    records: list[dict[str, object]] = []
    total = 0
    seen_toml: dict[str, str] = {}
    seen_source: dict[str, str] = {}
    for root, dirs, files in os.walk(build_dir, followlinks=False):
        dirs.sort()
        # A symlinked directory is not traversed (followlinks=False) but must
        # still refuse rather than silently skip.
        for name in list(dirs):
            full = Path(root) / name
            try:
                st = os.lstat(full)
            except OSError:
                raise Refusal("NOT_REGULAR_FILE", f"{full} cannot be stated")
            if stat.S_ISLNK(st.st_mode):
                raise Refusal("NOT_REGULAR_FILE", f"{full} is a symlink")
            if not stat.S_ISDIR(st.st_mode):
                raise Refusal("NOT_REGULAR_FILE", f"{full} is not a directory")
        for name in sorted(files):
            full = Path(root) / name
            rel = full.relative_to(build_dir).as_posix()
            if rel.startswith("/") or any(seg in ("", ".", "..") for seg in rel.split("/")):
                raise Refusal("UNSAFE_PATH", f"{rel} escapes the build directory")
            try:
                st = os.lstat(full)
            except OSError:
                raise Refusal("NOT_REGULAR_FILE", f"{rel} cannot be stated")
            if not stat.S_ISREG(st.st_mode):
                raise Refusal("NOT_REGULAR_FILE", f"{rel} is not a regular file")
            if st.st_size > MAX_BUILD_FILE_BYTES:
                raise Refusal("FILE_TOO_LARGE", f"{rel} exceeds {MAX_BUILD_FILE_BYTES} bytes")
            total += st.st_size
            if total > MAX_BUILD_TOTAL_BYTES:
                raise Refusal("TOTAL_TOO_LARGE", f"build output exceeds {MAX_BUILD_TOTAL_BYTES} bytes")
            with open(full, "rb") as fh:
                digest = sha256_hex(fh.read())
            base_toml_paths = baseline["tomlDigests"]
            assert isinstance(base_toml_paths, dict)
            if dist_only:
                # Strict dist-only mode (attest/upload re-derivation): every
                # path must sit under an enrolled extension's dist/ prefix.
                # TOML set equality is re-checked by `assemble` against the
                # extracted source tree instead.
                allowed = any(rel.startswith(prefix) for prefix in prefixes)
            else:
                allowed = any(rel.startswith(prefix) for prefix in prefixes)
                if not allowed and (rel in record_digests or rel in base_toml_paths):
                    allowed = True
            if not allowed:
                raise Refusal("UNEXPECTED_PATH", f"{rel} is not an enrolled dist path or baseline source file")
            records.append({"path": rel, "mode": "100644", "size": st.st_size, "sha256": digest})
            if not dist_only:
                if rel.endswith(".toml"):
                    seen_toml[rel] = digest
                elif rel in record_digests:
                    seen_source[rel] = digest
    records.sort(key=lambda r: str(r["path"]))

    if not dist_only:
        base_toml = baseline["tomlDigests"]
        assert isinstance(base_toml, dict)
        for path in sorted(set(base_toml) - set(seen_toml)):
            raise Refusal("TOML_REMOVED", f"{path} is missing from the build output")
        for path in sorted(set(seen_toml) - set(base_toml)):
            raise Refusal("TOML_ADDED", f"{path} is not in the baseline")
        for path in sorted(set(base_toml)):
            if base_toml[path] != seen_toml[path]:
                raise Refusal("TOML_CHANGED", f"{path} digest differs from the baseline")
        for path in sorted(seen_source):
            if record_digests.get(path) != seen_source[path]:
                raise Refusal("SOURCE_CHANGED", f"{path} differs from the enrolled source")

    manifest = {
        "records": records,
        "buildOutputDigest": sha256_hex(canonical_json(records)),
    }
    print(canonical_json(manifest).decode("utf-8"))
    return 0


# ---------------------------------------------------------------------------
# stage-dist
# ---------------------------------------------------------------------------


def cmd_stage_dist(args: argparse.Namespace) -> int:
    """Copy only enrolled ``dist/**`` outputs into the staging directory.

    Runs in the untrusted build job after the enrolled build recipe.
    Anything outside an enrolled extension's ``dist/`` prefix — including
    ``node_modules`` — is never staged, so it cannot reach a trusted job.
    Staged candidates that are symlinks or non-regular files refuse rather
    than skip: the build recipe must emit real files.
    """
    build_dir = Path(args.build_dir)
    if not build_dir.is_dir():
        raise Refusal("BUILD_DIR_INVALID", f"{args.build_dir} is not a directory")
    baseline = require_manifest_shape(load_json(args.baseline), "baseline")
    prefixes = dist_prefixes(baseline)
    if not prefixes:
        raise Refusal("NO_DIST_PREFIX", "the baseline enrolls no extension dist prefix")
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    staged = 0
    total = 0
    for root, dirs, files in os.walk(build_dir, followlinks=False):
        dirs.sort()
        for name in sorted(files):
            full = Path(root) / name
            rel = full.relative_to(build_dir).as_posix()
            if rel.startswith("/") or any(seg in ("", ".", "..") for seg in rel.split("/")):
                raise Refusal("UNSAFE_PATH", f"{rel} escapes the build directory")
            if not any(rel.startswith(prefix) for prefix in prefixes):
                continue
            total += copy_regular_file(full, rel, out_dir)
            if total > MAX_BUILD_TOTAL_BYTES:
                raise Refusal("TOTAL_TOO_LARGE", f"staged output exceeds {MAX_BUILD_TOTAL_BYTES} bytes")
            staged += 1
    if staged == 0:
        raise Refusal("NO_DIST_OUTPUT", "no enrolled dist file was staged")
    print(canonical_json({"ok": True, "staged": staged}).decode("utf-8"))
    return 0


# ---------------------------------------------------------------------------
# assemble
# ---------------------------------------------------------------------------


def cmd_assemble(args: argparse.Namespace) -> int:
    """Overlay staged dist files onto the extracted source tree (trusted job).

    Re-checks TOML set equality against the baseline, then copies only
    enrolled ``dist/**`` files from the staged build output into
    ``deploy-root/<app-root>/``. Any path collision refuses: build products
    must not overwrite enrolled source bytes. Nothing outside ``dist/**``
    is overlaid, so ``node_modules`` and other build-job residue never
    reaches the deploy directory.
    """
    deploy_root = Path(args.deploy_root)
    if not deploy_root.is_dir():
        raise Refusal("DEPLOY_ROOT_INVALID", f"{args.deploy_root} is not a directory")
    build_output = Path(args.build_output)
    if not build_output.is_dir():
        raise Refusal("BUILD_DIR_INVALID", f"{args.build_output} is not a directory")
    app_root = args.app_root
    if not is_safe_app_root(app_root or ""):
        raise Refusal("UNSAFE_PATH", "app-root must be a safe relative path")
    app_dir = deploy_root / app_root
    if not app_dir.is_dir():
        raise Refusal("DEPLOY_ROOT_INVALID", f"{app_root} is not in the deploy root")
    baseline = require_manifest_shape(load_json(args.baseline), "baseline")
    prefixes = dist_prefixes(baseline)
    if not prefixes:
        raise Refusal("NO_DIST_PREFIX", "the baseline enrolls no extension dist prefix")

    base_toml = baseline["tomlDigests"]
    assert isinstance(base_toml, dict)
    seen_toml: dict[str, str] = {}
    for root, dirs, files in os.walk(app_dir, followlinks=False):
        dirs.sort()
        for name in list(dirs):
            full = Path(root) / name
            try:
                st = os.lstat(full)
            except OSError:
                raise Refusal("NOT_REGULAR_FILE", f"{full} cannot be stated")
            if stat.S_ISLNK(st.st_mode):
                raise Refusal("NOT_REGULAR_FILE", f"{full} is a symlink")
        for name in sorted(files):
            full = Path(root) / name
            rel = full.relative_to(app_dir).as_posix()
            try:
                st = os.lstat(full)
            except OSError:
                raise Refusal("NOT_REGULAR_FILE", f"{rel} cannot be stated")
            if not stat.S_ISREG(st.st_mode):
                raise Refusal("NOT_REGULAR_FILE", f"{rel} is not a regular file")
            if not rel.endswith(".toml"):
                continue
            with open(full, "rb") as fh:
                seen_toml[rel] = sha256_hex(fh.read())
    for path in sorted(set(base_toml) - set(seen_toml)):
        raise Refusal("TOML_REMOVED", f"{path} is missing from the deploy root")
    for path in sorted(set(seen_toml) - set(base_toml)):
        raise Refusal("TOML_ADDED", f"{path} is not in the baseline")
    for path in sorted(set(base_toml)):
        if base_toml[path] != seen_toml[path]:
            raise Refusal("TOML_CHANGED", f"{path} digest differs from the baseline")

    overlaid = 0
    for root, _dirs, files in os.walk(build_output, followlinks=False):
        for name in sorted(files):
            full = Path(root) / name
            rel = full.relative_to(build_output).as_posix()
            if rel.startswith("/") or any(seg in ("", ".", "..") for seg in rel.split("/")):
                raise Refusal("UNSAFE_PATH", f"{rel} escapes the staged output")
            if not any(rel.startswith(prefix) for prefix in prefixes):
                raise Refusal("UNEXPECTED_PATH", f"{rel} is not an enrolled dist path")
            target = app_dir / rel
            if os.path.lexists(target):
                raise Refusal("PATH_COLLISION", f"{rel} already exists in the deploy root")
            copy_regular_file(full, rel, app_dir)
            overlaid += 1
    if overlaid == 0:
        raise Refusal("NO_DIST_OUTPUT", "no enrolled dist file was overlaid")
    print(canonical_json({"ok": True, "overlaid": overlaid}).decode("utf-8"))
    return 0


# ---------------------------------------------------------------------------
# claim-request
# ---------------------------------------------------------------------------

CLAIM_SCHEMA_VERSION = 1
NUMERIC_ID_RE = re.compile(r"^[0-9]{1,20}$")


def cmd_claim_request(args: argparse.Namespace) -> int:
    """Build the typed upload-claim body (W0 live slice, RND-4084 T400).

    Every int-typed field arrives as an argparse ``int`` so a string
    attempt (``githubRunAttempt: "2"``) fails at usage time, never as a
    silently quoted JSON string. The numeric artifact id is validated as
    digits and emitted as a JSON number. Generation is M5's 0-based
    generation (RND-4084 T403): 0 is the first preparation and is valid;
    negatives refuse.
    """
    generation = args.generation
    run_attempt = args.github_run_attempt
    if generation < 0:
        raise Refusal("CLAIM_FIELD_INVALID", "generation must be a non-negative integer")
    if run_attempt < 1:
        raise Refusal("CLAIM_FIELD_INVALID", "github-run-attempt must be a positive integer")
    for label, value in (
        ("workspace-id", args.workspace_id),
        ("preparation-nonce", args.preparation_nonce),
        ("requested-version", args.requested_version),
        ("trusted-workflow-ref", args.trusted_workflow_ref),
    ):
        if not isinstance(value, str) or not value or len(value) > 256:
            raise Refusal("CLAIM_FIELD_INVALID", f"{label} is required (1..256 chars)")
    for label, value in (
        ("github-repository-id", args.github_repository_id),
        ("github-run-id", args.github_run_id),
    ):
        if not isinstance(value, str) or not NUMERIC_ID_RE.match(value):
            raise Refusal("CLAIM_FIELD_INVALID", f"{label} must be a numeric id string")
    if not FULL_SHA_RE.match(args.trusted_workflow_sha or ""):
        raise Refusal("CLAIM_FIELD_INVALID", "trusted-workflow-sha must be a full 40-hex SHA")
    for label, value in (
        ("source-archive-digest", args.source_archive_digest),
        ("build-output-digest", args.build_output_digest),
    ):
        if not isinstance(value, str) or not HEX64_RE.match(value):
            raise Refusal("CLAIM_FIELD_INVALID", f"{label} must be sha256 hex")
    if not NUMERIC_ID_RE.match(args.build_artifact_id or ""):
        raise Refusal(
            "CLAIM_FIELD_INVALID",
            "build-artifact-id must be the numeric build-output artifact id, not its name",
        )
    manifest_raw = read_bounded(args.output_manifest, MAX_JSON_BYTES)
    try:
        manifest_text = manifest_raw.decode("utf-8")
        manifest = json.loads(manifest_text)
    except (ValueError, UnicodeDecodeError):
        raise Refusal("CLAIM_FIELD_INVALID", "output manifest is not valid JSON")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("buildOutputDigest"), str):
        raise Refusal("CLAIM_FIELD_INVALID", "output manifest must carry buildOutputDigest")
    if manifest["buildOutputDigest"] != args.build_output_digest:
        raise Refusal("CLAIM_FIELD_INVALID", "build-output-digest does not match the output manifest")

    body = {
        "schemaVersion": CLAIM_SCHEMA_VERSION,
        "workspaceId": args.workspace_id,
        "generation": generation,
        "preparationNonce": args.preparation_nonce,
        "requestedVersionName": args.requested_version,
        "githubRepositoryId": args.github_repository_id,
        "githubRunId": args.github_run_id,
        "githubRunAttempt": run_attempt,
        "trustedWorkflowRef": args.trusted_workflow_ref,
        "trustedWorkflowSha": args.trusted_workflow_sha,
        "sourceArchiveDigest": args.source_archive_digest,
        "buildOutputDigest": args.build_output_digest,
        "buildArtifactId": int(args.build_artifact_id),
        "outputManifest": manifest_text,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(canonical_json(body).decode("utf-8"))
        fh.write("\n")
    print(canonical_json({"ok": True, "path": args.out}).decode("utf-8"))
    return 0


# ---------------------------------------------------------------------------
# claim-gate
# ---------------------------------------------------------------------------


# Echo fields verified against the claim request body. deployRunId travels
# in the URL path rather than the body, so it is verified against the
# --deploy-run-id argv value instead.
GATE_ECHO_FIELDS = ("generation", "githubRunId", "githubRunAttempt", "requestedVersionName")


def cmd_claim_gate(args: argparse.Namespace) -> int:
    try:
        request = json.loads(read_bounded(args.request, MAX_JSON_BYTES).decode("utf-8"))
        response = json.loads(read_bounded(args.response, MAX_JSON_BYTES).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return emit_refusal("CLAIM_GATE_REFUSED", "claim response is not valid JSON")
    except Refusal as exc:
        if exc.code in ("INPUT_NOT_FOUND", "INPUT_UNREADABLE", "INPUT_TOO_LARGE"):
            raise
        return emit_refusal("CLAIM_GATE_REFUSED", exc.detail)
    if not isinstance(request, dict) or not isinstance(response, dict):
        return emit_refusal("CLAIM_GATE_REFUSED", "claim request and response must be JSON objects")
    if response.get("success") is not True:
        return emit_refusal("CLAIM_GATE_REFUSED", "success is not the boolean true")
    data = response.get("data")
    if not isinstance(data, dict):
        return emit_refusal("CLAIM_GATE_REFUSED", "response has no data envelope")
    if data.get("dispatchGranted") is not True:
        return emit_refusal("CLAIM_GATE_REFUSED", "dispatchGranted is not the boolean true")
    if data.get("deployRunId") != args.deploy_run_id:
        return emit_refusal("CLAIM_GATE_REFUSED", "deployRunId does not echo the request")
    for field in GATE_ECHO_FIELDS:
        expected = request.get(field)
        got = data.get(field)
        if type(got) is not type(expected) or got != expected:
            return emit_refusal("CLAIM_GATE_REFUSED", f"{field} does not echo the request")
    deadline_raw = data.get("startDeadlineAt")
    if not isinstance(deadline_raw, str) or not deadline_raw:
        return emit_refusal("CLAIM_GATE_REFUSED", "startDeadlineAt is missing")
    try:
        deadline = datetime.fromisoformat(deadline_raw)
    except ValueError:
        return emit_refusal("CLAIM_GATE_REFUSED", "startDeadlineAt is not ISO-8601")
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > deadline:
        return emit_refusal("CLAIM_GATE_REFUSED", "startDeadlineAt has passed")
    print(json.dumps({"ok": True}))
    return 0


# ---------------------------------------------------------------------------
# receipt-gate
# ---------------------------------------------------------------------------


def cmd_receipt_gate(args: argparse.Namespace) -> int:
    """Gate the receipt POST response (W0 live slice, RND-4084 T411).

    Exits 0 only when the response is the route's success envelope with
    the JSON boolean ``observed: true`` and the JSON boolean
    ``replay: false``. A replay answer (already observed) refuses: the
    live job posts exactly once, so a replay means the post was not the
    first and the job must fail loudly rather than report success.
    Anything else — a missing envelope, a string "true", an absent or
    non-boolean field — refuses.
    """
    try:
        response = json.loads(read_bounded(args.response, MAX_JSON_BYTES).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return emit_refusal("RECEIPT_GATE_REFUSED", "receipt response is not valid JSON")
    except Refusal as exc:
        if exc.code in ("INPUT_NOT_FOUND", "INPUT_UNREADABLE", "INPUT_TOO_LARGE"):
            raise
        return emit_refusal("RECEIPT_GATE_REFUSED", exc.detail)
    if not isinstance(response, dict):
        return emit_refusal("RECEIPT_GATE_REFUSED", "receipt response must be a JSON object")
    if response.get("success") is not True:
        return emit_refusal("RECEIPT_GATE_REFUSED", "success is not the boolean true")
    data = response.get("data")
    if not isinstance(data, dict):
        return emit_refusal("RECEIPT_GATE_REFUSED", "response has no data envelope")
    if data.get("observed") is not True:
        return emit_refusal("RECEIPT_GATE_REFUSED", "observed is not the boolean true")
    if data.get("replay") is not False:
        return emit_refusal("RECEIPT_GATE_REFUSED", "replay is not the boolean false")
    print(json.dumps({"ok": True}))
    return 0


# ---------------------------------------------------------------------------
# receipt
# ---------------------------------------------------------------------------


def find_secret_key(value: object) -> str | None:
    if isinstance(value, list):
        for entry in value:
            found = find_secret_key(entry)
            if found is not None:
                return found
        return None
    if isinstance(value, dict):
        for key, entry in value.items():
            if isinstance(key, str) and SECRET_KEY_RE.search(key):
                return key
            found = find_secret_key(entry)
            if found is not None:
                return found
    return None


def observe_candidate_version(path: str, requested_version: str) -> tuple[str, str]:
    """Resolve the observed candidate from a `versions list --json` capture.

    Strict, never heuristic: the capture must be a JSON array whose every
    record carries string ``versionTag``/``versionId``/``status``; exactly one
    record must name the requested version; that record must not be active
    (an unreleased candidate); and its id must be a Shopify Version GID.
    Anything else refuses with a typed code.
    """
    try:
        raw = load_json(path)
    except Refusal as exc:
        raise Refusal("VERSIONS_LIST_INVALID", f"versions list unreadable ({exc.code}): {exc.detail}")
    if not isinstance(raw, list):
        raise Refusal("VERSIONS_LIST_INVALID", "versions list must be a JSON array")
    for index, entry in enumerate(raw):
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("versionTag"), str)
            or not isinstance(entry.get("versionId"), str)
            or not isinstance(entry.get("status"), str)
        ):
            raise Refusal(
                "VERSIONS_LIST_INVALID",
                f"versions list record {index} must carry string versionTag, versionId and status",
            )
    matches = [entry for entry in raw if isinstance(entry, dict) and entry.get("versionTag") == requested_version]
    if len(matches) == 0:
        raise Refusal(
            "CANDIDATE_NOT_OBSERVED",
            f"the requested version {requested_version!r} is absent from the versions list",
        )
    if len(matches) > 1:
        raise Refusal(
            "CANDIDATE_AMBIGUOUS",
            f"the requested version {requested_version!r} appears {len(matches)} times in the versions list",
        )
    entry = matches[0]
    assert isinstance(entry, dict)
    if entry.get("status") == "active":
        raise Refusal(
            "CANDIDATE_ALREADY_ACTIVE",
            f"the requested version {requested_version!r} is already active, not an unreleased candidate",
        )
    version_id = entry.get("versionId")
    assert isinstance(version_id, str)
    if not VERSION_GID_RE.match(version_id):
        raise Refusal("VERSIONS_LIST_INVALID", f"versions list record for {requested_version!r} carries no Version GID")
    version_tag = entry.get("versionTag")
    assert isinstance(version_tag, str)
    return version_tag, version_id


def cmd_receipt(args: argparse.Namespace) -> int:
    baseline = require_manifest_shape(load_json(args.baseline), "baseline")
    manifest = require_manifest_shape(load_json(args.manifest), "manifest")
    output_raw = load_json(args.output)
    if not isinstance(output_raw, dict) or not isinstance(output_raw.get("buildOutputDigest"), str):
        raise Refusal("MANIFEST_INVALID", "output manifest must carry buildOutputDigest")
    claim_raw = load_json(args.claim)
    if not isinstance(claim_raw, dict):
        raise Refusal("MANIFEST_INVALID", "claim must be a JSON object")
    claim: dict[str, object] = claim_raw
    for field in (
        "workspaceId",
        "deployRunId",
        "appBindingId",
        "githubRepositoryId",
        "githubRunId",
        "trustedWorkflowSha",
        "sourceHash",
        "buildOutputDigest",
    ):
        if not isinstance(claim.get(field), str) or not claim[field]:
            raise Refusal("CLAIM_MISMATCH", f"claim is missing {field}")
    if claim.get("generation") != args.generation or claim.get("githubRunAttempt") != args.run_attempt:
        raise Refusal("CLAIM_MISMATCH", "generation or run attempt does not match the claim")
    if claim["sourceHash"] != manifest.get("sourceArchiveDigest"):
        raise Refusal("CLAIM_MISMATCH", "claim sourceHash does not match the source manifest")
    if claim["buildOutputDigest"] != output_raw["buildOutputDigest"]:
        raise Refusal("CLAIM_MISMATCH", "claim buildOutputDigest does not match the output manifest")
    for label, digest in (
        ("artifact", args.artifact_digest),
        ("image", args.image_digest),
        ("toolchain", args.toolchain_digest),
    ):
        if not HEX64_RE.match(digest or ""):
            raise Refusal("RECEIPT_FIELD_INVALID", f"{label} digest must be sha256 hex")
    if args.build_status not in ("succeeded", "failed"):
        raise Refusal("RECEIPT_FIELD_INVALID", "build-status must be succeeded or failed")
    if args.upload_status not in ("succeeded", "failed", "not_attempted"):
        raise Refusal("RECEIPT_FIELD_INVALID", "upload-status must be succeeded, failed or not_attempted")
    if not FULL_SHA_RE.match(claim["trustedWorkflowSha"]):  # type: ignore[index]
        raise Refusal("RECEIPT_FIELD_INVALID", "claim trustedWorkflowSha must be a full SHA")
    if not NUMERIC_ID_RE.match(args.artifact_id or ""):
        raise Refusal(
            "RECEIPT_FIELD_INVALID",
            "github artifact id must be the numeric build-output artifact id, not its name",
        )
    if not isinstance(manifest.get("commit"), str) or not FULL_SHA_RE.match(str(manifest.get("commit"))):
        raise Refusal("RECEIPT_FIELD_INVALID", "source manifest commit must be a full SHA")
    requested_version = claim.get("requestedVersionName")
    if not isinstance(requested_version, str) or not requested_version:
        raise Refusal("CLAIM_MISMATCH", "claim is missing requestedVersionName")

    if args.upload_status == "succeeded":
        if not args.versions:
            print(
                "usage: prepare.py receipt --versions <path> is required when --upload-status succeeded",
                file=sys.stderr,
            )
            return 2
        observed_tag, observed_id = observe_candidate_version(args.versions, requested_version)
    else:
        if args.versions:
            print(
                "usage: prepare.py receipt --versions must be absent unless --upload-status succeeded",
                file=sys.stderr,
            )
            return 2
        observed_tag, observed_id = None, None

    receipt: dict[str, object] = {
        "workspaceId": claim["workspaceId"],
        "deployRunId": claim["deployRunId"],
        "appBindingId": claim["appBindingId"],
        "generation": args.generation,
        "repositoryId": claim["githubRepositoryId"],
        "commitSha": manifest["commit"],
        "configName": manifest["configName"],
        "clientId": manifest["clientId"],
        "sourceArchiveDigest": manifest["sourceArchiveDigest"],
        "buildOutputDigest": output_raw["buildOutputDigest"],
        "tomlDigestsBefore": baseline["tomlDigests"],
        "tomlDigestsAfter": manifest["tomlDigests"],
        "extensionInventoryBefore": baseline["extensionInventory"],
        "extensionInventoryAfter": manifest["extensionInventory"],
        "trustedWorkflowRef": args.workflow_ref,
        "trustedWorkflowSha": claim["trustedWorkflowSha"],
        "githubRunId": claim["githubRunId"],
        "githubRunAttempt": args.run_attempt,
        "githubArtifactId": args.artifact_id,
        "githubArtifactDigest": args.artifact_digest,
        "imageDigest": args.image_digest,
        "toolchainDigest": args.toolchain_digest,
        "cliVersion": args.cli_version,
        "buildStatus": args.build_status,
        "uploadStatus": args.upload_status,
        "observedCandidateVersionTag": observed_tag,
        "observedCandidateVersionId": observed_id,
    }
    if list(receipt.keys()) != RECEIPT_KEYS:
        raise Refusal("RECEIPT_FIELD_INVALID", "receipt keys do not match AppBuildReceiptV1")
    secret = find_secret_key(receipt)
    if secret is not None:
        raise Refusal("SECRET_MATERIAL_REFUSED", f"receipt must not carry secret material (saw {secret})")
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(canonical_json(receipt).decode("utf-8"))
        fh.write("\n")
    print(canonical_json({"ok": True, "path": args.out}).decode("utf-8"))
    return 0


# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="prepare.py")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("source-manifest")
    p.add_argument("--repo", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--app-root", required=True)
    p.add_argument("--config-name", required=True)
    p.set_defaults(func=cmd_source_manifest)

    p = sub.add_parser("policy-check")
    p.add_argument("--baseline", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--client-id", required=True)
    p.set_defaults(func=cmd_policy_check)

    p = sub.add_parser("output-manifest")
    p.add_argument("--build-dir", required=True)
    p.add_argument("--baseline", required=True)
    p.add_argument("--dist-only", action="store_true")
    p.set_defaults(func=cmd_output_manifest)

    p = sub.add_parser("stage-dist")
    p.add_argument("--build-dir", required=True)
    p.add_argument("--baseline", required=True)
    p.add_argument("--out-dir", required=True)
    p.set_defaults(func=cmd_stage_dist)

    p = sub.add_parser("assemble")
    p.add_argument("--deploy-root", required=True)
    p.add_argument("--build-output", required=True)
    p.add_argument("--baseline", required=True)
    p.add_argument("--app-root", required=True)
    p.set_defaults(func=cmd_assemble)

    p = sub.add_parser("claim-request")
    p.add_argument("--workspace-id", required=True)
    p.add_argument("--generation", required=True, type=int)
    p.add_argument("--preparation-nonce", required=True)
    p.add_argument("--requested-version", required=True)
    p.add_argument("--github-repository-id", required=True)
    p.add_argument("--github-run-id", required=True)
    p.add_argument("--github-run-attempt", required=True, type=int)
    p.add_argument("--trusted-workflow-ref", required=True)
    p.add_argument("--trusted-workflow-sha", required=True)
    p.add_argument("--source-archive-digest", required=True)
    p.add_argument("--build-output-digest", required=True)
    p.add_argument("--build-artifact-id", required=True)
    p.add_argument("--output-manifest", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_claim_request)

    p = sub.add_parser("claim-gate")
    p.add_argument("--response", required=True)
    p.add_argument("--request", required=True)
    p.add_argument("--deploy-run-id", required=True)
    p.set_defaults(func=cmd_claim_gate)

    p = sub.add_parser("receipt-gate")
    p.add_argument("--response", required=True)
    p.set_defaults(func=cmd_receipt_gate)

    p = sub.add_parser("receipt")
    p.add_argument("--baseline", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--claim", required=True)
    p.add_argument("--generation", required=True, type=int)
    p.add_argument("--run-attempt", required=True, type=int)
    p.add_argument("--workflow-ref", required=True)
    p.add_argument("--artifact-id", required=True)
    p.add_argument("--artifact-digest", required=True)
    p.add_argument("--image-digest", required=True)
    p.add_argument("--toolchain-digest", required=True)
    p.add_argument("--cli-version", required=True)
    p.add_argument("--build-status", required=True)
    p.add_argument("--upload-status", required=True)
    p.add_argument("--versions", default=None)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_receipt)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Refusal as exc:
        return emit_refusal(exc.code, exc.detail)


if __name__ == "__main__":
    sys.exit(main())
