FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb AS build
COPY data/src/vaultlab.c /build/vaultlab.c
COPY data/src/compute_integrity.py /build/compute_integrity.py
RUN apt-get update && apt-get install -y --no-install-recommends gcc musl-tools binutils \
    && rm -rf /var/lib/apt/lists/* \
    && musl-gcc -static -O2 -fno-builtin-memcmp -fno-reorder-functions \
       -DINTEGRITY_EXPECT=0ULL -o /build/vaultlab_p1 /build/vaultlab.c \
    && IHASH=$(python3 /build/compute_integrity.py /build/vaultlab_p1) \
    && echo "Integrity hash: $IHASH" \
    && musl-gcc -static -O2 -fno-builtin-memcmp -fno-reorder-functions \
       -DINTEGRITY_EXPECT=${IHASH} -o /build/vaultlab /build/vaultlab.c \
    && strip /build/vaultlab \
    && rm /build/vaultlab.c /build/vaultlab_p1 /build/compute_integrity.py

FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb
RUN pip install --no-cache-dir --break-system-packages pytest==8.4.1 pytest-json-ctrf==0.3.5
COPY data/docs /app/data/docs
COPY data/fit /app/data/fit
COPY data/work /app/data/work
COPY --from=build /build/vaultlab /app/data/bin/vaultlab
RUN chmod 755 /app/data/bin/vaultlab && mkdir -p /app/output
WORKDIR /app
