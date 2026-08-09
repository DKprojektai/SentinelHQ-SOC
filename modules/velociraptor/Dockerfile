FROM ubuntu:22.04
LABEL version="Velociraptor v0.76.5"
LABEL description="Velociraptor server in a Docker container"
LABEL maintainer="Wes Lambert, @therealwlambert"
COPY ./entrypoint .
# Pin Velociraptor v0.76.5 via DIRECT release-asset URLs (no GitHub API/jq — that
# was rate-limit-prone and the tag is "v0.76", with the patch version only in the
# asset filename, which broke "releases/tags/v0.76.5" -> 404 -> jq null).
ARG VELO_VER=v0.76.5
ARG VELO_REL=v0.76
RUN chmod +x entrypoint && \
    apt-get update && \
    apt-get install -y curl wget jq rsync && \
    mkdir -p /opt/velociraptor && \
    for i in linux mac windows; do mkdir -p /opt/velociraptor/$i; done && \
    BASE="https://github.com/Velocidex/velociraptor/releases/download/${VELO_REL}" && \
    wget -O /opt/velociraptor/linux/velociraptor            "${BASE}/velociraptor-${VELO_VER}-linux-amd64" && \
    wget -O /opt/velociraptor/mac/velociraptor_client       "${BASE}/velociraptor-${VELO_VER}-darwin-amd64" && \
    wget -O /opt/velociraptor/windows/velociraptor_client.exe "${BASE}/velociraptor-${VELO_VER}-windows-amd64.exe" && \
    wget -O /opt/velociraptor/windows/velociraptor_client.msi "${BASE}/velociraptor-${VELO_VER}-windows-amd64.msi" && \
    apt-get remove -y --purge wget && \
    apt-get clean
WORKDIR /velociraptor
CMD ["/entrypoint"]
