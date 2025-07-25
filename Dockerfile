# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/base-debian12:debug-nonroot@sha256:20bc1021b26cbc67b9b40f8df10d97a06287312b19a5ae86092cb33d0fcd8ab5
COPY bin/manager /manager
USER 65532:65532

ENTRYPOINT ["/manager"]
