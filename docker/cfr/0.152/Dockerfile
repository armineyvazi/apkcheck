# CFR 0.152 — pinned artifact (never :latest).
# Build:
#   docker build -t apkcheck-cfr:0.152 -f docker/cfr/0.152/Dockerfile .
FROM eclipse-temurin:17-jre

LABEL org.apkcheck.tool="cfr"
LABEL org.apkcheck.version="0.152"
LABEL org.apkcheck.source="https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar"
LABEL org.apkcheck.sha256="f686e8f3ded377d7bc87d216a90e9e9512df4156e75b06c655a16648ae8765b2"

COPY tools/cfr-0.152.jar /opt/cfr.jar
WORKDIR /work
ENTRYPOINT ["java","-jar","/opt/cfr.jar"]
