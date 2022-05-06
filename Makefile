.PHONY: build
build:
	docker build \
		--tag qos \
		.

.PHONY: volume
volume:
	docker volume create qos

.PHONY: enclave
enclave: build volume
	docker run \
		--rm \
		-it \
		-v qos:/var/run/qos:rw \
		qos \
		./qos server --port 3000

.PHONY: client
client: build volume
	docker run \
		--rm \
		-it \
		-v qos:/var/run/qos:rw \
		qos \
		./qos client --cid 3 --port 5005

.PHONY: shell
shell: build volume
	docker run \
		--rm \
		-it \
		-v qos:/var/run/qos:rw \
		qos \
		bash

# server: build
# 	docker build -t vsock-sample-server -f Dockerfile.server .
# 	nitro-cli build-enclave --docker-uri vsock-sample-server --output-file vsock_sample_server.eif

# client: build
# 	docker build -t vsock-sample-client -f Dockerfile.client .
# 	nitro-cli build-enclave --docker-uri vsock-sample-client --output-file vsock_sample_client.eif

# .PHONY: clean
# clean:
# 	rm -rf ${RUST_DIR}/target ${RUST_DIR}/vsock_sample_*.eif ${RUST_DIR}/vsock-sample
