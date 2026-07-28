FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

ARG TARGETARCH

RUN microdnf install -y elfutils-libelf ca-certificates && \
    microdnf clean all

COPY dist/linux/${TARGETARCH}/tls-probe /usr/local/bin/tls-probe
COPY dist/linux/${TARGETARCH}/tls-probe-ebpf /usr/local/lib/tls-probe-ebpf

VOLUME /data

ENTRYPOINT ["tls-probe"]
CMD ["capture", "--ebpf", "/usr/local/lib/tls-probe-ebpf", "--interface", "all", "--output", "/data/capture.json"]
