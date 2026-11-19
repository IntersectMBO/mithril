ARG DOCKER_IMAGE_FROM=debian:13-slim
FROM $DOCKER_IMAGE_FROM

# Upgrade
RUN apt-get update -y && apt-get install -y libssl-dev ca-certificates wget adduser && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create appuser
RUN adduser --no-create-home --disabled-password appuser

# Precreate workdir
RUN mkdir -p /app/bin

#Workdir
WORKDIR /app/

## Download Disk usage exporter
ARG DISK_USAGE_EXPORTER_VERSION=0.6.0
ARG DISK_USAGE_EXPORTER_URL=https://github.com/dundee/disk_usage_exporter/releases/download/v$DISK_USAGE_EXPORTER_VERSION/disk_usage_exporter_linux_386.tgz
RUN wget $DISK_USAGE_EXPORTER_URL \
    && tar xzf disk_usage_exporter_linux_386.tgz \
    && chmod u+x disk_usage_exporter_linux_386 \
    && mv disk_usage_exporter_linux_386 /app/bin/disk_usage_exporter \
    && rm -f disk_usage_exporter_linux_386.tgz

# Use an unprivileged user
USER appuser

# Run the executable
ENTRYPOINT ["/app/bin/disk_usage_exporter"]