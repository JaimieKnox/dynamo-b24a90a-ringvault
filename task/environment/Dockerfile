FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb AS build
COPY data/src/vaultlab.c /build/vaultlab.c
RUN apt-get update && apt-get install -y --no-install-recommends gcc musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && musl-gcc -static -O2 -o /build/vaultlab /build/vaultlab.c \
    && strip /build/vaultlab \
    && rm /build/vaultlab.c

FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb
RUN pip install --no-cache-dir --break-system-packages pytest==8.4.1 pytest-json-ctrf==0.3.5
COPY data/docs /app/data/docs
COPY data/fit /app/data/fit
COPY data/work /app/data/work
COPY --from=build /build/vaultlab /app/data/bin/vaultlab
RUN chmod 755 /app/data/bin/vaultlab && mkdir -p /app/output
WORKDIR /app
