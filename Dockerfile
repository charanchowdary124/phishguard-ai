FROM maven:3.9-eclipse-temurin-25-alpine AS build
WORKDIR /workspace
COPY pom.xml .
COPY src ./src
RUN mvn -B clean package

FROM eclipse-temurin:25-jre-alpine
WORKDIR /app
COPY --from=build /workspace/target/phishguard-ai-1.0.0.jar app.jar
EXPOSE 8080
USER 10001:10001
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
