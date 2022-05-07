.PHONY: build
build:
	docker build \
		--tag apeclave \
		.

.PHONY: volume
volume:
	docker volume create vapecave

.PHONY: server
server: build volume
	docker run \
		--rm \
		-v vapecave:/var/run/vapecave:rw \
		apeclave \
		server

.PHONY: client
client: build volume
	docker run \
		--rm \
		-v vapecave:/var/run/vapecave:rw \
		apeclave \
		client

.PHONY: shell
shell: build volume
	docker run \
		--rm \
		-it \
		-v vapecave:/var/run/vapecave:rw \
		bash
