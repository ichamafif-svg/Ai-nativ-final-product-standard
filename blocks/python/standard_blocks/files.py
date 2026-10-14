"""Files from users (UPLOAD-LIMITS, UPLOAD-TYPE, ARCHIVE-SAFE, UPLOAD-NOEXEC, PATH-SAFE, FILENAME-SERVE, AV-SCAN,
FILE-METADATA).

    fid = await files.receive(upload, owner=user.id)
    return files.serve(fid, owner=user.id, as_name="report.pdf")

Files are stored by a generated id under STANDARD_FILES_DIR, never under their own name, never executable, never in
a folder the web server serves. The type is read from the content, not from the name.

Beyond the checklists:
    - an archive is measured by decompressing it, not by what its headers claim: entries are read in chunks and
      stopped at @unpacked_max_bytes, and an entry that inflates more than MAX_RATIO times is a bomb;
    - a PDF that carries active content (JavaScript, launch actions, embedded files) in its readable structure is
      refused (names decoded first); content hidden in compressed object streams is left to the scan hook;
    - files are served as attachments in a sandbox (CSP `sandbox; default-src 'none'`), so a polyglot that a browser
      would read as HTML runs nothing even if opened inline;
    - files are opened without following links (O_NOFOLLOW), so a link planted in the store reads nothing.
"""
from __future__ import annotations

import io
import os
import re
import struct
import unicodedata
import zipfile
from pathlib import Path
from urllib.parse import quote

from starlette.exceptions import HTTPException

from . import Values
from . import log
from .crypto import digest, token

CHUNK = 65_536
MAX_RATIO = 100
PDF_ACTIVE = re.compile(rb"/(JavaScript|JS|Launch|EmbeddedFile|RichMedia|XFA|OpenAction\s*<<[^>]*/S\s*/JavaScript)\b")
MAGIC = [(b"\x89PNG\r\n\x1a\n", "image/png"), (b"\xff\xd8\xff", "image/jpeg"), (b"GIF87a", "image/gif"),
         (b"GIF89a", "image/gif"), (b"%PDF-", "application/pdf"), (b"PK\x03\x04", "application/zip")]
FID = re.compile(r"[A-Za-z0-9_-]{20,64}")


class FileRejected(HTTPException):
    """A refusal the web layer answers with its status (413 too large, 415 wrong type, 404, 409, 422)."""

    def __init__(self, status: int, reason: str):
        super().__init__(status_code=status, detail=reason)
        self.status = status


def sniff(head: bytes) -> str:
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    return next((t for magic, t in MAGIC if head.startswith(magic)), "application/octet-stream")


def pixels(data: bytes, kind: str) -> int | None:
    if kind == "image/webp" and len(data) >= 30:
        chunk = data[12:16]
        if chunk == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
            w, h = struct.unpack("<HH", data[26:30])
            return (w & 0x3FFF) * (h & 0x3FFF)
        if chunk == b"VP8L" and data[20] == 0x2F:
            b = data[21:25]
            w = 1 + (((b[1] & 0x3F) << 8) | b[0])
            h = 1 + (((b[3] & 0xF) << 10) | (b[2] << 2) | ((b[1] & 0xC0) >> 6))
            return w * h
        if chunk == b"VP8X":
            w = 1 + int.from_bytes(data[24:27], "little")
            h = 1 + int.from_bytes(data[27:30], "little")
            return w * h
        return None
    if kind == "image/png" and len(data) >= 24:
        w, h = struct.unpack(">II", data[16:24])
        return w * h
    if kind == "image/gif" and len(data) >= 10:
        w, h = struct.unpack("<HH", data[6:10])
        return w * h
    if kind == "image/jpeg":
        i = 2
        while i + 9 < len(data):
            if data[i] != 0xFF:
                return None
            marker, size = data[i + 1], struct.unpack(">H", data[i + 2:i + 4])[0]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                h, w = struct.unpack(">HH", data[i + 5:i + 9])
                return w * h
            i += 2 + size
    return None


def strip_metadata(data: bytes, kind: str) -> bytes:
    """JPEG without APP1..APP15 and comments; PNG without text, EXIF and time chunks."""
    if kind == "image/jpeg":
        out, i = bytearray(data[:2]), 2
        while i + 4 <= len(data) and data[i] == 0xFF:
            marker = data[i + 1]
            if marker == 0xDA:                               # start of scan: the rest is image data
                out += data[i:]
                return bytes(out)
            size = struct.unpack(">H", data[i + 2:i + 4])[0]
            if not (0xE1 <= marker <= 0xEF or marker == 0xFE):
                out += data[i:i + 2 + size]
            i += 2 + size
        return bytes(out + data[i:])
    if kind == "image/png":
        out, i = bytearray(data[:8]), 8
        while i + 12 <= len(data):
            n = struct.unpack(">I", data[i:i + 4])[0]
            kind_ = data[i + 4:i + 8]
            if kind_ not in (b"tEXt", b"iTXt", b"zTXt", b"eXIf", b"tIME"):
                out += data[i:i + 12 + n]
            i += 12 + n
        return bytes(out)
    return data


class Files:
    def __init__(self, values: Values | None = None, root=None, scan=None):
        """root: where files live (STANDARD_FILES_DIR), outside any folder the web server serves. scan: a callable
        bytes -> bool (True = clean), the hook to an antivirus (AV-SCAN); None keeps files unserved until scanned."""
        self.values = values or Values.from_env()
        self.root = Path(root or os.environ.get("STANDARD_FILES_DIR", "var/files")).resolve()
        self.scan = scan

    def _dir(self, owner: str) -> Path:
        d = self.root / digest(owner.encode())[:32]
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        return d

    def _used(self, owner: str) -> int:
        return sum(p.stat().st_size for p in self._dir(owner).glob("*") if p.is_file())

    def _archive(self, data: bytes) -> None:
        v = self.values
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            raise FileRejected(415, "not a readable archive") from None
        infos = z.infolist()
        if len(infos) > int(v["archive_max_files"]):
            raise FileRejected(413, "too many entries")
        if sum(i.file_size for i in infos) > int(v["unpacked_max_bytes"]):
            raise FileRejected(413, "too large once unpacked")
        for i in infos:
            mode = i.external_attr >> 16
            if (mode & 0o170000) == 0o120000:
                raise FileRejected(415, "an archive entry is a link")
            name = i.filename
            if name.startswith(("/", "\\")) or ".." in re.split(r"[\\/]", name) or ":" in name or "\x00" in name \
                    or len(name) > 255 or unicodedata.normalize("NFC", name) != name:
                raise FileRejected(415, "an archive entry leaves its folder")

    async def receive(self, upload, *, owner: str) -> str:
        """Read an upload within the limits, check its real type, strip metadata, store it by id. Returns the id."""
        v, limit = self.values, int(self.values["upload_max_bytes"])
        buf = bytearray()
        while chunk := await upload.read(CHUNK):
            buf += chunk
            if len(buf) > limit:
                log.security("upload.too_large", who=owner)
                raise FileRejected(413, "file too large")
        data = bytes(buf)
        kind = sniff(data[:16])
        if kind not in v["upload_types"]:
            raise FileRejected(415, "type not accepted")
        if kind.startswith("image/"):
            n = pixels(data, kind)
            if n is None or n > int(v["image_max_pixels"]):
                raise FileRejected(413, "image too large")
            data = strip_metadata(data, kind)
        if kind == "application/zip":
            self._archive(data)
            self._inflate(data)
        if kind == "application/pdf" and (PDF_ACTIVE.search(data) or PDF_ACTIVE.search(
                re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m[1], 16)]), data))):     # /J#61vaScript
            log.security("upload.active_pdf", who=owner)
            raise FileRejected(415, "a PDF with active content")
        if self._used(owner) + len(data) > int(v["user_quota_bytes"]):
            raise FileRejected(413, "storage quota reached")
        fid = token(24)
        path = self._dir(owner) / fid
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        if self.scan is not None and not self.scan(data):
            path.unlink()
            raise FileRejected(422, "the file did not pass the scan")
        if self.scan is not None:
            (self._dir(owner) / f"{fid}.scanned").touch(mode=0o600)
        log.event("upload.stored", who=owner, id=fid, size=len(data), kind=kind)
        return fid

    def _inflate(self, data: bytes) -> dict:
        """Decompress every entry in chunks, stopping at @unpacked_max_bytes and at MAX_RATIO per entry."""
        limit, total, out = int(self.values["unpacked_max_bytes"]), 0, {}
        z = zipfile.ZipFile(io.BytesIO(data))
        for info in z.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise FileRejected(415, "an encrypted archive entry")
            got = bytearray()
            with z.open(info) as f:
                while chunk := f.read(CHUNK):
                    got += chunk
                    total += len(chunk)
                    if total > limit:
                        raise FileRejected(413, "too large once unpacked")
                    if len(got) > MAX_RATIO * max(info.compress_size, 1) + CHUNK:
                        raise FileRejected(413, "an archive entry inflates like a bomb")
            out[info.filename] = bytes(got)
        return out

    def read(self, fid: str, *, owner: str) -> bytes:
        if not isinstance(fid, str) or not FID.fullmatch(fid):
            raise FileRejected(404, "no such file")
        path = self._dir(owner) / fid
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            raise FileRejected(404, "no such file") from None
        with os.fdopen(fd, "rb") as f:
            return f.read()

    def serve(self, fid: str, *, owner: str, as_name: str = "file"):
        """The file as an attachment, with a name the app chose, encoded (RFC 6266). Unscanned files are not served
        when a scanner is configured."""
        from starlette.responses import Response
        if self.scan is not None and not (self._dir(owner) / f"{fid}.scanned").exists():
            raise FileRejected(409, "the file is waiting for its scan")
        data = self.read(fid, owner=owner)
        ascii_name = unicodedata.normalize("NFKD", as_name).encode("ascii", "ignore").decode()
        ascii_name = re.sub(r"[^A-Za-z0-9._-]", "_", ascii_name)[:100] or "file"
        disposition = f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(as_name[:100], safe='')}"
        return Response(data, media_type=sniff(data[:16]), headers={
            "content-disposition": disposition, "content-security-policy": "sandbox; default-src 'none'",
            "x-content-type-options": "nosniff", "cross-origin-resource-policy": "same-origin",
            "cache-control": "private, no-store"})

    def unpack(self, fid: str, *, owner: str) -> dict:
        """An archive's files in memory, name -> bytes, after the same checks as at upload."""
        data = self.read(fid, owner=owner)
        self._archive(data)
        return self._inflate(data)
