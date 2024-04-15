FROM debian:bookworm-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    make \
	python3

WORKDIR /opt/rwm
COPY rwm.py Makefile ./
RUN make install

ENTRYPOINT ["/opt/rwm/rwm.py"]
