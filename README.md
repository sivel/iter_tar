# iter_tar
Python library to iterate through a tar file

## Example

```python
with open('archive.tar', 'rb') as f:
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
```
