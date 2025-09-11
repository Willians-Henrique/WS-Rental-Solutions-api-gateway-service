FROM openjdk:21-jdk-slim

# Install Maven AND netcat-openbsd
RUN apt-get update && apt-get install -y maven netcat-openbsd && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy pom.xml first for dependency caching
COPY pom.xml .

# Download dependencies (this layer will be cached)
RUN mvn dependency:resolve

# Copy source code
# COPY src ./src

# Expose port
EXPOSE 8080

CMD ["mvn", "spring-boot:run"]