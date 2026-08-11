FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb AS build
COPY data/ringvault /build/ringvault
RUN python3 - <<'PY'
import compileall
import shutil
from pathlib import Path
root = Path('/build/ringvault')
for path in root.rglob('__pycache__'):
    shutil.rmtree(path, ignore_errors=True)
for path in root.rglob('*.pyc'):
    path.unlink(missing_ok=True)
ok = compileall.compile_dir(str(root), force=True, quiet=1, legacy=True)
if not ok:
    raise SystemExit('compileall failed')
for path in list(root.rglob('*.py')):
    path.unlink()
for path in root.rglob('__pycache__'):
    shutil.rmtree(path, ignore_errors=True)
needed = {'__init__.pyc', 'lab.pyc', 'seal.pyc', 'protocol.pyc', '__main__.pyc'}
have = {p.name for p in root.glob('*.pyc')}
if not needed.issubset(have):
    raise SystemExit(f'missing pyc: {needed - have}')
print('legacy bytecode ready', sorted(have))
PY

FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb
RUN pip install --no-cache-dir --break-system-packages pytest==8.4.1 pytest-json-ctrf==0.3.5
COPY data/docs /app/data/docs
COPY data/fit /app/data/fit
COPY data/work /app/data/work
COPY data/tools /app/data/tools
COPY --from=build /build/ringvault /app/data/ringvault
RUN mkdir -p /app/output
WORKDIR /app
