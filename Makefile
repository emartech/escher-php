tests: ## Run tests in docker
	@docker-compose up -d --build
	@docker-compose run web /bin/bash -l -c "/var/www/html/vendor/bin/phpunit -c /var/www/html/test/phpunit.xml"