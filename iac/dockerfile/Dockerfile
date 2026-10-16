# File:    Dockerfile
# Purpose: IaC fixture. Container build with an unpinned base image, root user,
#          embedded secrets, exposed database/SSH ports, remote scripts piped
#          into a shell, ADD over COPY and no healthcheck.
#          Intentionally misconfigured - never build or run.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
#
# Expected rules: DOCKER-001 (latest tag), DOCKER-002 (runs as root),
#   DOCKER-003 (no healthcheck), DOCKER-004 (many RUN layers),
#   DOCKER-005 (secrets in ENV), DOCKER-006 (ADD instead of COPY),
#   DOCKER-007 (cache not cleaned), DOCKER-008 (SSH port),
#   DOCKER-009 (no WORKDIR), DOCKER-010 (apt-get upgrade),
#   DOCKER-012 (sudo), DOCKER-013 (/bin/sh in RUN),
#   DOCKER-014..018 (MySQL/Postgres/Mongo/Redis/RDP ports),
#   DOCKER-019/020 (curl and wget piped to shell)

FROM ubuntu:latest

# Secrets baked into image layers and into the environment
ENV DB_PASSWORD=FixturePassw0rd
ENV API_KEY=ak_live_docker_0123456789abcdef
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ARG GITHUB_TOKEN=ghp_FIXTURE00000000000000000000000000000

# Unpredictable upgrade, cache left behind, many separate layers
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y curl wget openssh-server sudo
RUN apt-get install -y python3 python3-pip
RUN apt-get install -y nginx

# Remote code downloaded and executed without verification
RUN curl -fsSL https://install.example.com/setup.sh | sh
RUN wget -qO- https://install.example.com/agent.sh | bash

# Shell form with an explicit /bin/sh and sudo inside the build
RUN /bin/sh -c "echo build step"
RUN sudo chmod 777 /opt/app

# ADD performs implicit extraction and URL fetching
ADD https://releases.example.com/app.tar.gz /opt/
ADD ./bundle.tar.gz /opt/app/

# World-writable application directory
RUN chmod -R 777 /opt/app

# Remote access and database ports published from the container
EXPOSE 22
EXPOSE 3306
EXPOSE 5432
EXPOSE 27017
EXPOSE 6379
EXPOSE 3389
EXPOSE 80

# No USER instruction, so the container runs as root.
# No WORKDIR, no HEALTHCHECK.
CMD ["nginx", "-g", "daemon off;"]
