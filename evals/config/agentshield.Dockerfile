# Same base as the release image: chainguard/static supplies CA certificates, which the
# model-calling features need for HTTPS, and the nonroot user 65532.
FROM cgr.dev/chainguard/static@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
COPY agentshield /agentshield
USER 65532:65532
ENTRYPOINT ["/agentshield"]
