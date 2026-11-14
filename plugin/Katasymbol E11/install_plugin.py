#!/usr/bin/env python3

import os
from pathlib import Path
import stat
import sys
import tempfile

base = os.environ.get('DISKPASS_PRIVATE_DIR', '')
base = Path(base) if base.startswith('/') else Path.home() / '.diskpass'
for directory in (base, base / 'plugins'):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = directory.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise SystemExit(f'Refusing non-private directory: {directory}')
target = base / 'plugins' / Path(sys.argv[1]).name
if len(sys.argv) > 2 and sys.argv[2] == '--remove':
    target.unlink(missing_ok=True)
    raise SystemExit(0)
fd, temporary = tempfile.mkstemp(prefix='.install-', dir=base / 'plugins')
try:
    with os.fdopen(fd, 'wb') as output:
        output.write(Path(sys.argv[1]).read_bytes())
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, base / 'plugins' / Path(sys.argv[1]).name)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
print(base / 'plugins' / Path(sys.argv[1]).name)
