ARG ARCH=amd64

FROM arhatdev/builder-go:alpine as builder

ARG ARCH=amd64
ARG CNI_PLUGINS_VERSION="v0.8.7"

COPY scripts/image/download.sh /download
RUN set -e;\
    sh /download cni_plugins "${ARCH}" "${CNI_PLUGINS_VERSION}"

FROM arhatdev/go:alpine-${ARCH}

COPY --from=builder /opt/cni/bin /opt/cni/bin

# add required packages
RUN set -e ;\
    apk --no-cache add iptables ip6tables ;

ENTRYPOINT [ "/abbot" ]
