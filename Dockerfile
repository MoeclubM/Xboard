ARG SWOOLE_IMAGE=phpswoole/swoole:php8.2-alpine@sha256:98a3bbe5d35a169125fcf5581ade5a0befc55a3d797177ca66ca185eaf4045c4
ARG PHP_PATCH_VERSION=8.2.35
ARG PHP_PATCH_SHA256=5737b98601fe5ab1b8c5db0c82ed3158acb9283ed3081ffe2faffb9ac81455e6

FROM ${SWOOLE_IMAGE} AS php-build

ARG PHP_PATCH_VERSION
ARG PHP_PATCH_SHA256
ARG PHP_BUILD_JOBS=2

# Build PHP against the same Alpine libraries and extension ABI as Swoole.
RUN set -eux; \
    apk add --no-cache --virtual .php-build-deps \
        $PHPIZE_DEPS argon2-dev coreutils curl-dev gnu-libiconv-dev \
        libsodium-dev libxml2-dev linux-headers oniguruma-dev openssl-dev \
        readline-dev sqlite-dev; \
    rm -f /usr/include/iconv.h; \
    configure_options="$(php-config --configure-options)"; \
    docker-php-source delete; \
    curl --fail --show-error --location --retry 3 \
        "https://www.php.net/distributions/php-${PHP_PATCH_VERSION}.tar.xz" \
        --output /usr/src/php.tar.xz; \
    echo "${PHP_PATCH_SHA256}  /usr/src/php.tar.xz" | sha256sum -c -; \
    docker-php-source extract; \
    cd /usr/src/php; \
    export CFLAGS="$PHP_CFLAGS" CPPFLAGS="$PHP_CPPFLAGS" LDFLAGS="$PHP_LDFLAGS"; \
    ./configure $configure_options; \
    make -j "$PHP_BUILD_JOBS"; \
    make install; \
    cp php.ini-* "$PHP_INI_DIR/"; \
    strip --strip-all /usr/local/bin/php /usr/local/bin/php-cgi /usr/local/bin/phpdbg; \
    test "$(php -r 'echo PHP_VERSION;')" = "$PHP_PATCH_VERSION"

FROM ${SWOOLE_IMAGE}

ARG PHP_PATCH_VERSION
ARG PHP_PATCH_SHA256
ENV PHP_VERSION=${PHP_PATCH_VERSION} \
    PHP_URL=https://www.php.net/distributions/php-${PHP_PATCH_VERSION}.tar.xz \
    PHP_ASC_URL=https://www.php.net/distributions/php-${PHP_PATCH_VERSION}.tar.xz.asc \
    PHP_SHA256=${PHP_PATCH_SHA256}

COPY --from=php-build /usr/local/ /usr/local/
COPY --from=php-build /usr/src/php.tar.xz /usr/src/php.tar.xz

COPY --from=mlocati/php-extension-installer /usr/bin/install-php-extensions /usr/local/bin/

# Install PHP extensions one by one with lower optimization level for ARM64 compatibility
RUN apk upgrade --no-cache && \
    rm -f /usr/src/php.tar.xz.asc && \
    CFLAGS="-O0" install-php-extensions pcntl && \
    CFLAGS="-O0 -g0" install-php-extensions bcmath && \
    install-php-extensions zip && \
    install-php-extensions redis && \
    apk --no-cache add shadow sqlite mysql-client mysql-dev mariadb-connector-c git patch supervisor redis caddy && \
    addgroup -S -g 1000 www && adduser -S -G www -u 1000 www && \
    (getent group redis || addgroup -S redis) && \
    (getent passwd redis || adduser -S -G redis -H -h /data redis)

WORKDIR /www

COPY .docker /

# Add build arguments
ARG CACHEBUST=1
ARG REPO_URL=https://github.com/MoeclubM/Xboard
ARG BRANCH_NAME=master
ARG SOURCE_REVISION
ARG APP_VERSION

RUN test -n "${CACHEBUST}" && \
    rm -rf ./* && \
    rm -rf .git && \
    git config --global --add safe.directory /www && \
    git init . && \
    git remote add origin "${REPO_URL}" && \
    git fetch --depth 1 origin "${SOURCE_REVISION:-${BRANCH_NAME}}" && \
    git checkout --detach FETCH_HEAD && \
    git submodule update --init --recursive --force && \
    if [ -n "${APP_VERSION}" ]; then \
        sed -i "s/'version' => '.*'/'version' => '${APP_VERSION}'/g" config/app.php; \
    fi

COPY .docker/supervisor/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY .docker/caddy/Caddyfile /etc/caddy/Caddyfile
COPY .docker/php/zz-xboard.ini /usr/local/etc/php/conf.d/zz-xboard.ini

RUN composer install --no-cache --no-dev --no-security-blocking \
    && php artisan storage:link \
    && chown -R www:www /www \
    && chmod -R 775 /www \
    && mkdir -p /data \
    && chown redis:redis /data

RUN php -r 'if (PHP_VERSION !== getenv("PHP_VERSION") || PHP_VERSION_ID < 80235) { fwrite(STDERR, "PHP security version check failed\n"); exit(1); } foreach (["swoole", "redis", "pdo_mysql", "pcntl", "bcmath", "sockets", "zip", "sodium", "Zend OPcache"] as $extension) { if (!extension_loaded($extension)) { fwrite(STDERR, "Missing extension: ".$extension."\n"); exit(1); } } echo "PHP ".PHP_VERSION."; Swoole ".phpversion("swoole")."\n";' \
    && composer check-platform-reqs --no-dev \
    && php artisan --version
    
ENV ENABLE_WEB=true \
    ENABLE_HORIZON=true \
    ENABLE_REDIS=true \
    ENABLE_WS_SERVER=true \
    ENABLE_CADDY=true

EXPOSE 7001
COPY .docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"] 
