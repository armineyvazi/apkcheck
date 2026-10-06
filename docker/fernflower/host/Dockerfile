# FernFlower host-jar image template.
# Set FERNFLOWER jar path/sha256 in versions.yaml before enabling docker runner.
FROM eclipse-temurin:17-jre

LABEL org.apkcheck.tool="fernflower"
COPY tools/versions/fernflower/host/fernflower.jar /opt/fernflower.jar
WORKDIR /work
ENTRYPOINT ["java","-jar","/opt/fernflower.jar"]
