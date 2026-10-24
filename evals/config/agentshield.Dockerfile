# Same base as the release image: distroless/static supplies CA certificates, which the
# model-calling features need for HTTPS, and the nonroot user 65532.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
COPY agentshield /agentshield
USER 65532:65532
ENTRYPOINT ["/agentshield"]
