IMAGE_NAME:=ss/datadog-forwarder
IMAGE_REPO := 810605503585.dkr.ecr.us-east-1.amazonaws.com/$(IMAGE_NAME)
IMAGE_URI := $(IMAGE_REPO):$(IMAGE_VERSION)
IMAGE_VERSION := $(shell date +%Y%m%d%H%M)
FUNCTION_NAME := SS-OPS-1-datadog-forwarder
REGION := us-east-1

docker-build:
	DOCKER_BUILDKIT=1 docker build --pull \
		--secret id=known_hosts,src=$(HOME)/.ssh/known_hosts \
	    --secret id=ssh_key,src=$(HOME)/.ssh/rakuten \
		-t $(IMAGE_NAME) .

docker-push: docker-build
	docker tag $(IMAGE_NAME):latest $(IMAGE_URI)
	docker push $(IMAGE_URI)

login:
	$$(aws ecr get-login --region ${REGION} --no-include-email)

pull:
	docker pull $(IMAGE_URI)

run:
	docker run \
		-v ~/.aws:/root/.aws \
		-e AWS_DEFAULT_REGION=us-east-1 \
		-it $(IMAGE_NAME) bash

deploy: docker-push
	./deploy.sh $(FUNCTION_NAME)
