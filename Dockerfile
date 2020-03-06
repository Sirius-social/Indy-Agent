FROM ubuntu:16.04

ARG VERSION='0.0'
ARG indy_version=1.14.2
ARG indy_release=1510

RUN useradd -ms /bin/bash indy

# Install environment
RUN apt-get update -y && apt-get install -y \
	coreutils \
	wget \
	curl \
	python3.5 \
	python3-pip \
	python-setuptools \
	apt-transport-https \
	ca-certificates \
	software-properties-common \
	libssl-dev \
	cargo \
	libsodium-dev \
	libzmq3-dev \
	iputils-ping \
	telnet \
	pkg-config \
	&& apt-get clean

ENV LANG C.UTF-8
ENV PYTHONUNBUFFERED 1
ENV VERSION ${VERSION}

# Install INDY
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys CE7709D068DB5E88 \
    && add-apt-repository "deb https://repo.sovrin.org/sdk/deb xenial master" \
    && apt-get update \
    && apt-get install -y libindy=${indy_version}~${indy_release} libvcx libnullpay \
    && apt-get clean

ADD plugins /plugins

RUN cd /plugins/postgres_storage && cargo build && cp target/debug/*.so /usr/lib && cd / && rm -r /plugins


# Copy project files and install dependencies
ADD app /app
RUN	ln -sf /usr/bin/python3 /usr/bin/python && \
    ln -sf /usr/bin/pip3 /usr/bin/pip && \
    pip install -r /app/requirements.txt && \
    chmod +x /app/wait-for-it.sh && \
    chmod +x /app/run_tests.sh
RUN pip install -U python3-indy==${indy_version} python3-wrapper-vcx

USER indy

# Environment
WORKDIR /app
ENV PYTHONPATH=/app:$PYTHONPATH
ENV PORT=8888
ENV WORKERS=4
EXPOSE 8888


HEALTHCHECK --interval=60s --timeout=3s --start-period=30s \
  CMD curl -f http://localhost:$PORT/maintenance/check_health/ || exit 1
# FIRE!!!
CMD /app/wait-for-it.sh ${DATABASE_HOST}:${DATABASE_PORT-5432} --timeout=60 && \
  cd /app && \
  python manage.py migrate && \
  python manage.py initialize && \
  daphne -p $PORT -b 0.0.0.0 settings.asgi:application
