FROM eclipse-temurin:17-jre-alpine

# Keep in sync with <version> in pom.xml. Was pinned to a 1.0.0 JAR that has not been
# built for several releases, so every image build failed until this was corrected.
ARG AGENT_VERSION=1.4.0

RUN apk add --no-cache bind-tools && addgroup -S agent && adduser -S agent -G agent

WORKDIR /app

COPY target/certops-agent-${AGENT_VERSION}.jar app.jar

RUN mkdir -p /var/certops-agent/spool && chown -R agent:agent /var/certops-agent

USER agent

ENTRYPOINT ["java", "-jar", "app.jar"]
