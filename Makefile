.PHONY: test

build: ; docker compose build

install: ; docker compose run --rm web composer install
update: ; docker compose run --rm web composer update

test: ; docker compose run --rm web php -d error_reporting=E_ALL ./vendor/bin/phpunit --do-not-cache-result -c phpunit.xml
test-only: ; docker compose run --rm web ./vendor/bin/phpunit --do-not-cache-result --group only -c phpunit.xml

