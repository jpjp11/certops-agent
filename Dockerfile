FROM eclipse-temurin:17-jre-alpine

RUN apk add --no-cache bind-tools && addgroup -S agent && adduser -S agent -G agent

WORKDIR /app

COPY target/certops-agent-1.0.0.jar app.jar

RUN mkdir -p /var/certops-agent/spool && chown -R agent:agent /var/certops-agent

USER agent

ENTRYPOINT ["java", "-jar", "app.jar"]
