# Same base as the release image: distroless/static supplies CA certificates, which the
# model-calling features need for HTTPS, and the nonroot user 65532.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY agentshield /agentshield
USER 65532:65532
ENTRYPOINT ["/agentshield"]
