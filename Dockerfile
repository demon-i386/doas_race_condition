# VIPER TESTS: doas (built from source) + exploit TOCTOU CWE-367
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libpam0g-dev \
    make \
    bison \
    git \
    ca-certificates \
    nano \
    vim \
    inotify-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Build doas from source (vulnerable version with TOCTOU in doasedit)
RUN git clone https://codeberg.org/thejessesmith/doas.git /tmp/doas-src && \
    cd /tmp/doas-src && \
    make CC=gcc SYSCONFDIR=/etc && \
    make install SYSCONFDIR=/etc && \
    rm -rf /tmp/doas-src

# doas.conf: root and victim can use doas (attacker cannot); nopass for non-interactive use
# victim runs doasedit; doas cp inside doasedit executes as root
RUN echo "permit nopass root as root" > /etc/doas.conf && \
    echo "permit nopass victim as root" >> /etc/doas.conf && \
    chmod 0400 /etc/doas.conf

# User attacker: regular user, no doas access
RUN useradd -m -s /bin/bash attacker

# User victim: has doas, can use doasedit
RUN useradd -m -s /bin/bash victim

# Exploit TOCTOU: compile and place in attacker's home
COPY exploit_toctou_write.c /home/attacker/exploit_toctou_write.c
RUN gcc -O2 -o /home/attacker/exploit_toctou_write /home/attacker/exploit_toctou_write.c && \
    chown attacker:attacker /home/attacker/exploit_toctou_write /home/attacker/exploit_toctou_write.c

# Prepare target dir (world-writable so attacker can set up the race)
RUN mkdir -p /tmp/toctou_race && chmod 777 /tmp/toctou_race

USER attacker
WORKDIR /home/attacker

CMD ["/bin/bash"]
