FROM --platform=linux/amd64 rust:1.85-bookworm AS builder

RUN echo "Installing eBPF build dependencies..." && \
    apt-get update && apt-get install -y \
    clang-16 \
    llvm-16 \
    llvm-16-dev \
    libclang-16-dev \
    libpolly-16-dev \
    libelf-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

ENV LLVM_SYS_160_PREFIX=/usr/lib/llvm-16

RUN echo "Installing Rust nightly and rust-src for eBPF..." && \
    rustup install nightly && \
    rustup component add rust-src --toolchain nightly

RUN echo "Installing bpf-linker..." && \
    cargo +nightly install bpf-linker

WORKDIR /app
COPY . .

RUN echo "Building eBPF probe..." && \
    cargo xtask build-ebpf

RUN echo "Building tls-probe CLI..." && \
    cargo build -p tls-probe --release

FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libelf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/tls-probe /usr/local/bin/tls-probe
COPY --from=builder /app/target/bpfel-unknown-none/release/tls-probe-ebpf /usr/local/lib/tls-probe-ebpf

ENTRYPOINT ["tls-probe"]
CMD ["--help"]
