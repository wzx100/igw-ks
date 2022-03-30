#!/bin/bash
ARCH=$(uname -m)
if [ "$ARCH" == "x86_64" ]; then
   echo "x86_64"
   wget https://downs1.dude6.com/14981137.gz?response-content-disposition=attachment%3Bfilename%3D%22helm-v3.5.1-linux-amd64.tar.gz%22&response-content-type=application%2Foctet-stream&OSSAccessKeyId=LTAIlrjwU50WD8RY&Expires=1648609802&Signature=HGVnFibOH%2FHPguaI%2FqU5JRUpsMk%3D && \
   tar xvf helm-"${HELM_VERSION}"-linux-amd64.tar.gz && \
   rm helm-"${HELM_VERSION}"-linux-amd64.tar.gz && \
   mv linux-amd64/helm /usr/bin/ && \
   rm -rf linux-amd64
elif [ "$ARCH" == "aarch64" ]; then
   echo "arm arch"
   wget https://downs1.dude6.com/14981137.gz?response-content-disposition=attachment%3Bfilename%3D%22helm-v3.5.1-linux-amd64.tar.gz%22&response-content-type=application%2Foctet-stream&OSSAccessKeyId=LTAIlrjwU50WD8RY&Expires=1648609802&Signature=HGVnFibOH%2FHPguaI%2FqU5JRUpsMk%3D && \
   tar xvf helm-"${HELM_VERSION}"-linux-arm64.tar.gz && \
   rm helm-"${HELM_VERSION}"-linux-arm64.tar.gz && \
   mv linux-arm64/helm /usr/bin/ && \
   rm -rf linux-arm64
fi
