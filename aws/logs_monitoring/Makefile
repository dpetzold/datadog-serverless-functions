IMAGE_NAME:=ss/auto-blocker
IMAGE_URI := 810605503585.dkr.ecr.us-east-1.amazonaws.com/$(IMAGE_NAME)
IMAGE_VERSION := $(shell date +%Y%m%d%H%M)
REGION := us-east-1

docker-build:
	DOCKER_BUILDKIT=1 docker build --pull \
		--secret id=known_hosts,src=$(HOME)/.ssh/known_hosts \
	    --secret id=ssh_key,src=$(HOME)/.ssh/rakuten \
		-t $(IMAGE_NAME) .

docker-push: docker-build
	docker tag $(IMAGE_NAME):latest $(IMAGE_URI):$(IMAGE_VERSION)
	docker push $(IMAGE_URI):$(IMAGE_VERSION)

login:
	$$(aws ecr get-login --region ${REGION} --no-include-email)

pull:
	docker pull $(IMAGE_URI):$(IMAGE_VERSION)

run-writer:
	login pull
	docker run \
		-v ~/.aws:/root/.aws \
		-e AWS_DEFAULT_REGION=us-east-1 \
		-e DYNACONF_ENV_NAME=ops \
		-e DYNACONF_IP_SET_ENV=prod \
		-e DYNACONF_WAF_ENABLED=1 \
		-it $(IMAGE_NAME) --prod --writer
