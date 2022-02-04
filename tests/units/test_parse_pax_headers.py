import io
import tarfile
import threading

import iter_tar


def test_parse_pax_headers():
    pax_headers = {
        'hdrcharset': 'BINARY',
        'path': 'föö/bãr/báz',
        'mtime': '1629988096.956',
    }

    t = tarfile.TarInfo()
    t.pax_headers = pax_headers
    data = io.BytesIO(
        t.create_pax_header(t.get_info(), 'utf-8')
    )

    entry = iter_tar.TarEntry(data, data.read(512), threading.Lock())
    assert iter_tar._parse_pax_headers(entry) == pax_headers
