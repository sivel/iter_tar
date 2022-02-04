# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT

"""Read from tar format archives.

This module provides only a simple interface for iterating
the entries of a tar archive, and provides no direct means of extracting
those entries directly to disk.

Additionally, this module operates as a stream from the tar archive
and does not provide a means to directly extract a single entry.

    >>> with open('archive.tar', 'rb') as f:
            found = None
            for entry in iter_tar(f):
                if str(entry.name) == 'sentinel.txt':
                    found = entry
            if found is None:
                raise KeyError('sentinel.txt')
            with found.name.open(mode='wb') as out:
                shutil.copyfileobj(found, out)
                out.seek(found.size)
                out.truncate()
            found.name.chmod(found.mode)
            os.chown(found.name, found.uid, found.gid)

"""

import array as _array
import collections.abc as _collections_abc
import io as _io
import mmap as _mmap
import pathlib as _pathlib
import re as _re
import sys as _sys
import tarfile as _tarfile
import threading as _threading
import typing as _typing
from struct import unpack_from as _unpack_from
from tarfile import nti as _tarfile_nti  # type: ignore
from tarfile import nts as _tarfile_nts  # type: ignore

__version__ = '0.0.1'
__all__ = ('TarEntry', 'iter_tar')

_ENCODING = _sys.getfilesystemencoding()
_ERRORS = 'surrogateescape'

_EXT_HEADERS = frozenset((
    _tarfile.XHDTYPE, _tarfile.XGLTYPE, _tarfile.SOLARIS_XHDTYPE,
    _tarfile.GNUTYPE_LONGNAME, _tarfile.GNUTYPE_LONGLINK,
))
_GNU_LONG_HEADERS = frozenset((
    _tarfile.GNUTYPE_LONGNAME, _tarfile.GNUTYPE_LONGLINK
))
_PAX_HEADER_RE = _re.compile(br'(\d+) ([^=]+)=([^\n]+)\n')
_PAX_HDRCHARSET_RE = _re.compile(br'\d+ hdrcharset=([^\n]+)\n')
_PAX_OVERRIDE_FIELDS = frozenset((
    'uname',
    'gname',
    'size',
    'mtime',
    'uid',
    'gid',
))

_TypingBytesLike = _typing.Union[
    bytes,
    bytearray,
    memoryview,
    _array.array,
    _mmap.mmap,
]


class TarEntry:
    """Object that holds information about a particular entry in a tar archive
    """
    def __init__(
        self,
        fp: _typing.BinaryIO,
        header: bytes,
        lock: _threading.Lock,
        pax_headers: _typing.Optional[dict[str, str]] = None,
        gnu_long: _typing.Optional[dict[str, str]] = None,
    ):

        self._fp = fp
        self._header = header
        self._lock = lock
        self.pax_headers: dict[str, str] = pax_headers or {}
        self._gnu_long: dict[str, str] = gnu_long or {}

        self._name: _typing.Optional[str] = None
        self.mode: int = _tarfile_nti(header[100:108])
        self.uid: int = _tarfile_nti(header[108:116])
        self.gid: int = _tarfile_nti(header[116:124])
        self._size: int = _tarfile_nti(header[124:136])
        self.mtime: int = _tarfile_nti(header[136:148])
        # TODO: Validate checksum here?
        self.checksum: int = _tarfile_nti(header[148:156])
        self.type: bytes = header[156:157]
        self._linkname: str = _tarfile_nts(header[157:257], _ENCODING, _ERRORS)
        self.uname: str = _tarfile_nts(header[265:297], _ENCODING, _ERRORS)
        self.gname: str = _tarfile_nts(header[297:329], _ENCODING, _ERRORS)
        self.devmajor: int = _tarfile_nti(header[329:337])
        self.devminor: int = _tarfile_nti(header[337:345])

        with self._lock:
            self._position = fp.tell()

    def __getattribute__(
        self,
        name: str,
    ) -> _typing.Union[str, int, float]:

        if name not in _PAX_OVERRIDE_FIELDS:
            # Not overridden by PaxHeader
            return object.__getattribute__(self, name)

        try:
            value = self.pax_headers[name]
        except KeyError:
            # No override by PaxHeader
            return object.__getattribute__(self, name)

        try:
            return _tarfile.PAX_NUMBER_FIELDS[name](value)
        except ValueError:
            return 0
        except KeyError:
            return value

    def gnu_sparse(
            self,
            name: str,
    ) -> _typing.Optional[str]:
        """Helper method for fetching ``GNU.sparse.*`` PAX headers
        """
        return self.pax_headers.get(f'GNU.sparse.{name}')

    @property
    def name(self) -> _pathlib.Path:
        """Name of the entry in the tarfile
        """
        if self._name:
            return _pathlib.Path(self._name)

        sparse_name = self.pax_headers.get('GNU.sparse.name')
        long_name = self._gnu_long.get('name')
        pax_name = self.pax_headers.get('path')

        prefix: _typing.Optional[str]
        name: str

        if sparse_name:
            prefix = None
            name = sparse_name
        elif long_name:
            prefix = None
            name = long_name
        elif pax_name:
            prefix = None
            name = pax_name
        else:
            prefix = _tarfile_nts(self._header[345:500], _ENCODING, _ERRORS)
            name = _tarfile_nts(self._header[0:100], _ENCODING, _ERRORS)

        if self.type not in _tarfile.GNU_TYPES and prefix:
            self._name = f'{prefix}/{name}'
        else:
            self._name = name

        return _pathlib.Path(self._name)

    @property
    def linkname(self) -> _typing.Optional[_pathlib.Path]:
        """Link name of the entry in the tarfile
        """
        longlink: _typing.Optional[str] = self._gnu_long.get('linkname')
        linkpath: _typing.Optional[str] = self.pax_headers.get('linkpath')
        linkname: _typing.Optional[str] = (
            longlink or linkpath or self._linkname
        )
        if linkname:
            return _pathlib.Path(linkname)
        return None

    @property
    def size(self) -> int:
        """Size of the entry in the tarfile
        """
        size = self._size
        pax_size: _typing.Optional[str] = self.pax_headers.get('size')
        sparse_size: _typing.Optional[str] = (
            self.gnu_sparse('size') or self.gnu_sparse('realsize')
        )
        return int(sparse_size or pax_size or size)

    def is_checksum_valid(self) -> bool:
        """Determine ff the checksum of the header is valid
        """
        checksums: tuple[int, int] = (
            256 + sum(_unpack_from('148B8x356B', self._header)),  # unsigned
            256 + sum(_unpack_from('148b8x356b', self._header))  # signed
        )
        return self.checksum in checksums

    def is_dir(self) -> bool:
        """Determine if the entry type is a directory
        """
        return self.type == _tarfile.DIRTYPE

    def is_file(self) -> bool:
        """Determine if the entry type is a regular file
        """
        return self.type in _tarfile.REGULAR_TYPES

    def is_symlink(self) -> bool:
        """Determine if the entry type is a symlink
        """
        return self.type == _tarfile.SYMTYPE

    def is_sparse(self) -> bool:
        """Determine if the entry type is a sparse file
        """
        return any((
            self.type == _tarfile.GNUTYPE_SPARSE,
            self.pax_headers.get('GNU.sparse.realsize'),
        ))

    def is_char_device(self) -> bool:
        """Determine if the entry type is a CHR device
        """
        return self.type == _tarfile.CHRTYPE

    def is_block_device(self) -> bool:
        """Determine if the entry type is a BLK device
        """
        return self.type == _tarfile.BLKTYPE

    def is_fifo(self) -> bool:
        """Determine if the entry type is a FIFO
        """
        return self.type == _tarfile.FIFOTYPE

    def seek(
        self,
        offset: int,
        whence: int = _io.SEEK_SET,
    ) -> int:
        """Move to new file position.

        Argument offset is a byte count.  Optional argument whence defaults to
        io.SEEK_SET or 0 (offset from start of entry, offset should be >= 0);
        other values are io.SEEK_CUR or 1 (move relative to current position,
        positive or negative), and io.SEEK_END or 2 (move relative to end of
        entry, must be negative, does not allow seeking beyond the end of an
        entry).
        """
        with self._lock:
            return self._seek(offset, whence)

    def _seek(
        self,
        offset: int,
        whence: int = _io.SEEK_SET,
    ) -> int:

        end = self._position + self._size
        cur = self._fp.tell()
        new = cur + offset
        conditions = (
            whence == _io.SEEK_SET and offset > self._size,
            whence == _io.SEEK_CUR and new > end,
            whence == _io.SEEK_CUR and new < self._position,
            whence == _io.SEEK_END and offset > 0,
            whence == _io.SEEK_END and new < self._position,
        )

        if any(conditions):
            raise ValueError(
                f'seek cannot exceed entry size: {self._size}'
            )

        if whence == _io.SEEK_SET:
            offset = self._position + offset
        elif whence == _io.SEEK_END:
            offset = end + offset
            whence = _io.SEEK_SET
        elif whence != _io.SEEK_CUR:
            offset = self._position + offset

        return self._fp.seek(offset, whence) - self._position

    def tell(self) -> int:
        """Return an int indicating the current stream position.
        """
        with self._lock:
            return self._tell()

    def _tell(self) -> int:
        end = self._position + self._size
        cur = self._fp.tell()
        relative = cur - self._position
        if cur > end or relative < 0:
            raise OSError('position outside of entry bounds')
        return relative

    def read(
        self,
        size: _typing.Optional[int] = -1,
    ) -> bytes:
        """Read up to size bytes of the tar entry as specified by the entry
        header and return them. As a convenience, if size is unspecified
        or -1, all bytes until the end of this tar entry are returned.

        This method will seek to the start of the entry in the underlying
        file handle if the current position lies outside of the location in
        the tar entry. If the position lies inside of the location in the
        tar entry, the stream position is unmodified before reading, allowing
        for multiple calls to retrieve partial bytes of the entry to
        conserve memory.
        """
        with self._lock:
            return self._read(size)

    def _read(
        self,
        size: _typing.Optional[int] = -1,
    ) -> bytes:

        end = self._position + self._size
        cur = self._fp.tell()
        if cur < self._position or cur > end:
            self._fp.seek(self._position)
            cur = self._position

        remaining = end - cur

        if size is None or size == -1 or size > remaining:
            size = remaining

        return self._fp.read(size)

    def readinto(
        self,
        b: _TypingBytesLike,
    ) -> int:
        """Read bytes into a pre-allocated, writable bytes-like object b,
        and return the number of bytes read. For example, b might be a
        bytearray.
        """
        with self._lock:
            return self._readinto(b)

    def _readinto(
        self,
        b: _TypingBytesLike,
    ) -> int:

        m = memoryview(b).cast('B')
        data = self.read(len(m))
        n = len(data)
        m[:n] = data
        return n

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} {self.name!r} at {id(self):#x}>'


def _parse_pax_headers(
    entry: TarEntry,
    headers: _typing.Optional[dict[str, str]] = None,
) -> _typing.Optional[dict[str, str]]:

    if not entry.is_checksum_valid():
        return headers

    if headers is None:
        headers = {}
    else:
        headers = headers.copy()

    header = entry.read()
    hdrcharset = _PAX_HDRCHARSET_RE.search(header)
    if hdrcharset:
        encoding = hdrcharset.group(1).decode('utf-8', 'strict')
        if encoding == 'BINARY':
            encoding = _ENCODING
    else:
        encoding = 'utf-8'
    for length, key, value in _PAX_HEADER_RE.findall(header):
        if not int(length):
            # TODO: Exception?
            continue
        key = key.decode('utf-8', _ERRORS)
        value = value.decode(encoding, _ERRORS)
        headers[key] = value

    return headers


def _parse_gnu_headers(
    entry: TarEntry,
    headers: _typing.Optional[dict[str, str]] = None,
) -> _typing.Optional[dict[str, str]]:

    if not entry.is_checksum_valid():
        return headers

    if headers is None:
        headers = {}
    else:
        headers = headers.copy()

    if entry.type == _tarfile.GNUTYPE_LONGNAME:
        key = 'name'
    elif entry.type == _tarfile.GNUTYPE_LONGLINK:
        key = 'linkname'
    headers[key] = _tarfile_nts(entry.read(), _ENCODING, _ERRORS)

    return headers


def _is_binary_fileobj(
    obj: _typing.IO,
) -> bool:

    return isinstance(obj, (_io.RawIOBase, _io.BufferedIOBase))


def iter_tar(
    f: _typing.BinaryIO,
) -> _collections_abc.Generator[TarEntry, None, None]:
    """Iterate over a file handle for a tar archive, and yield ``TarEntry``
    objects representing individual entries.

    tar archives allows a path to appear multiple times, with the last one
    having precedence.
    """
    if not _is_binary_fileobj(f):
        raise TypeError('binary file object required')

    lock = _threading.Lock()
    global_headers: _typing.Optional[dict[str, str]] = None
    pax_headers: _typing.Optional[dict[str, str]] = None
    gnu_long: _typing.Optional[dict[str, str]] = None
    while True:
        with lock:
            header = f.read(512)
            header_end = f.tell()

        if not header:
            break

        if header.count(b'\0') == 512:
            continue

        entry = TarEntry(
            f,
            header,
            lock,
            pax_headers=pax_headers,
            gnu_long=gnu_long,
        )

        if entry.type == _tarfile.XGLTYPE:
            global_headers = _parse_pax_headers(entry)
        elif entry.type in (_tarfile.XHDTYPE, _tarfile.SOLARIS_XHDTYPE):
            pax_headers = _parse_pax_headers(entry, global_headers)
        elif entry.type in _GNU_LONG_HEADERS:
            gnu_long = _parse_gnu_headers(entry)
        else:
            pax_headers = None
            gnu_long = None

        if entry.type not in _EXT_HEADERS and entry.name:
            yield entry

        end = header_end + entry._size
        mod = end % 512
        with lock:
            if mod:
                f.seek(end + 512 - mod)
            else:
                f.seek(end)
