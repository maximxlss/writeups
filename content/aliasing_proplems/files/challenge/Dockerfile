FROM rustlang/rust:nightly-slim@sha256:ec953af0da4a312cc6abfefe58d943183ee348d3b2cd665b3a957b18faa63460 AS cargo_chroot

RUN apt-get update && apt-get install -y pkg-config libssl-dev

RUN cargo install cargo-prefetch
RUN cargo prefetch libc@=0.2.174
RUN cargo prefetch seccompiler@=0.5.0

FROM gcr.io/kctf-docker/challenge@sha256:9f15314c26bd681a043557c9f136e7823414e9e662c08dde54d14a6bfd0b619f

COPY --from=cargo_chroot / /cargo_chroot
RUN chown -R 1000:1000 /cargo_chroot

COPY --from=ubuntu:22.04@sha256:3c61d3759c2639d4b836d32a2d3c83fa0214e36f195a3421018dbaaf79cbe37f / /exec_chroot
RUN chown -R 1000:1000 /exec_chroot

COPY src/ src/

COPY exec_nsjail.cfg cargo_nsjail.cfg /

COPY common.py server.py /

RUN mkdir /exec_chroot/flags
COPY flag.txt /exec_chroot/flags/
RUN chown -R 1000:1000 /exec_chroot/flags

CMD kctf_setup && \
    mount -t tmpfs tmpfs /tmp && \
    kctf_drop_privs socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow python3 server.py",stderr,pty,icanon=0,echo=0
