# Same base as the release image: distroless/static supplies CA certificates, which the
# model-calling features need for HTTPS, and the nonroot user 65532.
FROM gcr.io/distroless/static-debian13:nonroot
COPY agentshield /agentshield
USER 65532:65532
ENTRYPOINT ["/agentshield"]
