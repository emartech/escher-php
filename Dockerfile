FROM php:7.3-alpine3.15

ENV COMPOSER_ALLOW_SUPERUSER 1
ENV COMPOSER_HOME /tmp
ENV COMPOSER_VERSION 2.2.23

RUN set -eux ; \
  apk add --no-cache --virtual .composer-rundeps \
    bash \
    coreutils \
    git \
    make \
    openssh-client \
    patch \
    subversion \
    tini \
    bzip2 \
    bzip2-dev \
    zlib \
    zlib-dev \
    libzip \
    libzip-dev \
    unzip \
    zip

RUN set -eux ; \
  # install necessary/useful extensions not included in base image
  docker-php-ext-install \
    bz2 \
    zip \
  ; \
  # download installer.php, see https://getcomposer.org/download/
  curl \
    --silent \
    --fail \
    --location \
    --retry 3 \
    --output /tmp/installer.php \
    --url https://raw.githubusercontent.com/composer/getcomposer.org/f24b8f860b95b52167f91bbd3e3a7bcafe043038/web/installer \
  ; \
  # install composer phar binary
  php /tmp/installer.php \
    --no-ansi \
    --install-dir=/usr/bin \
    --filename=composer \
    --version=${COMPOSER_VERSION} \
  ; \
  composer --ansi --version --no-interaction ; \
  composer diagnose ; \
  rm -f /tmp/installer.php ; \
  find /tmp -type d -exec chmod -v 1777 {} + \
