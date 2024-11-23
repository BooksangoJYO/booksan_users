FROM eclipse-temurin:17-jdk-jammy as builder
VOLUME /tmp
COPY build/libs/booksan_users-0.0.1-SNAPSHOT.jar app.jar
ENV USE_POST 8080
ENTRYPOINT ["java","-jar", "-Dserver.port=${USE_POST}", "/app.jar"]

#maven로 된 프로젝트일 경우 -> docker build --build-arg JAR_FILE=target/*.jar -t masungil/devops:0.1  .
#gradle로 된 프로젝트일 경우 -> docker build -t masungil/devops:0.1  .