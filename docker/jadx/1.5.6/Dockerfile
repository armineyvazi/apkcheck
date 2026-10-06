# JADX pinned image template.
# Replace VERSION and SHA256 before enabling in configs/versions.yaml.
# Example build (after placing extracted jadx under tools/versions/jadx/1.5.6):
#   docker build -t apkcheck-jadx:1.5.6 -f docker/jadx/1.5.6/Dockerfile .
FROM eclipse-temurin:17-jre

LABEL org.apkcheck.tool="jadx"
LABEL org.apkcheck.version="1.5.6"

# Expect host build context to include a verified jadx distribution.
COPY tools/versions/jadx/1.5.6 /opt/jadx
ENV PATH="/opt/jadx/bin:${PATH}"
WORKDIR /work
ENTRYPOINT ["jadx"]
