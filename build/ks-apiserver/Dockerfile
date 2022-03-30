# Copyright 2020 The KubeSphere Authors. All rights reserved.
# Use of this source code is governed by an Apache license
# that can be found in the LICENSE file.

# Download dependencies
FROM alpine:3.11 as base_os_context

ARG TARGETARCH
ARG TARGETOS
ARG HELM_VERSION=v3.5.1

ENV OUTDIR=/out
RUN mkdir -p ${OUTDIR}/usr/local/bin/

WORKDIR /tmp

RUN apk add --no-cache ca-certificates

# install helm
ADD https://downs1.dude6.com/14981137.gz?response-content-disposition=attachment%3Bfilename%3D%22helm-v3.5.1-linux-amd64.tar.gz%22&response-content-type=application%2Foctet-stream&OSSAccessKeyId=LTAIlrjwU50WD8RY&Expires=1648609802&Signature=HGVnFibOH%2FHPguaI%2FqU5JRUpsMk%3D /tmp
RUN tar xvzf /tmp/helm-${HELM_VERSION}-${TARGETOS}-${TARGETARCH}.tar.gz -C /tmp
RUN mv /tmp/${TARGETOS}-${TARGETARCH}/helm ${OUTDIR}/usr/local/bin/

# Build 
FROM golang:1.16.3 as build_context

ENV OUTDIR=/out
RUN mkdir -p ${OUTDIR}/usr/local/bin/

WORKDIR /workspace
ADD . /workspace/

RUN make ks-apiserver
RUN mv /workspace/bin/cmd/ks-apiserver ${OUTDIR}/usr/local/bin/

##############
# Final image
#############

FROM alpine:3.11 

COPY --from=base_os_context /out/ /
COPY --from=build_context /out/ /

WORKDIR /

EXPOSE 9090
CMD ["sh"]
