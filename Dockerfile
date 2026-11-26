# make release cross-compiles with the patched, pinned local Go toolchain.
# The image build itself has no base-image download, compiler or package manager.
FROM scratch
ARG TARGETARCH
COPY dist/kig-linux-${TARGETARCH} /kig
USER 65532:65532
ENTRYPOINT ["/kig"]
