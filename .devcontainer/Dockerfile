ARG VARIANT=bullseye
FROM mcr.microsoft.com/vscode/devcontainers/base:${VARIANT}

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /tmp
ENV LDFLAGS -lrt

RUN apt update \
    && apt install -y build-essential git \
    libcairo2-dev \
    libjpeg62-turbo-dev \
    libpng-dev \
    libtool-bin \
    uuid-dev \
    libavcodec-dev libavformat-dev libavutil-dev libswscale-dev \
    freerdp2-dev \
    libpango1.0-dev \
    libssh2-1-dev \
    libtelnet-dev \
    libvncserver-dev \
    libwebsockets-dev \
    libpulse-dev \
    libssl-dev \
    libvorbis-dev \
    libwebp-dev \
    && git clone --depth 1 --branch 1.5.4 https://github.com/apache/guacamole-server.git \
    && cd /tmp/guacamole-server \
    && autoreconf -fi \
    && ./configure \
    && make -j4 \
    && make install \
    && rm -rfv /tmp/guacamole-server \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
ENV JAVA_HOME /usr/lib/jvm/java-11-openjdk-amd64
ENV PATH $JAVA_HOME/bin:$PATH

RUN apt update \
    && apt install -y openjdk-11-jdk maven \
    tomcat9 tomcat9-admin tomcat9-common tomcat9-user \
    && git clone --depth 1 --branch 1.5.4 https://github.com/apache/guacamole-client.git \
    && cd /tmp/guacamole-client \
    && JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 mvn package \
    && cp -v /tmp/guacamole-client/guacamole/target/guacamole-1.5.4.war /var/lib/tomcat9/webapps/guacamole.war \
    && echo "GUACAMOLE_HOME=/etc/guacamole" >> /etc/default/tomcat9 \
    && rm -rfv /tmp/guacamole-client \
    && rm -rf /var/lib/apt/lists/*

RUN ln -s /workspaces/guacamole-dataprovider-yml/data/home /usr/share/tomcat9/.guacamole \
    && ln -s /workspaces/guacamole-dataprovider-yml/data/home /etc/guacamole