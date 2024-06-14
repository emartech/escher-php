.PHONY: test

build: ; docker compose build

install: ; docker compose run --rm web composer install
update: ; docker compose run --rm web composer update

test: ; docker compose run --rm web composer test
test-only: ; docker compose run --rm web ./vendor/bin/phpunit --do-not-cache-result --group only -c phpunit.xml

