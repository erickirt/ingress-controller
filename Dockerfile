# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/base-debian12:debug-nonroot@sha256:d53efe9604cae04e8c02df63e3b22040c64e2db505e0074325a6bc1b710a0ada
COPY bin/manager /manager
USER 65532:65532

ENTRYPOINT ["/manager"]
