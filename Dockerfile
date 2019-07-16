FROM python:3.7

ARG VERSION='0.0'

RUN useradd -ms /bin/bash indy

# Install environment
RUN apt-get update -y && apt-get install -y \
	coreutils \
	wget \
	apt-transport-https \
	ca-certificates \
	software-properties-common

ENV LANG C.UTF-8
ENV PYTHONUNBUFFERED 1
ENV VERSION ${VERSION}

# Copy project files and install dependencies
ADD app /app
RUN	pip install -r /app/requirements.txt && chmod +x /app/wait-for-it.sh

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
  python manage.py migrate && \
  (python manage.py supervisor $WORKERS & gunicorn --bind 0.0.0.0:$PORT --workers=$WORKERS settings.wsgi)
