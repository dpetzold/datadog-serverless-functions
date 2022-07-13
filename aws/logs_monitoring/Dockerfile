# syntax=docker/dockerfile:1.0-experimental

FROM public.ecr.aws/lambda/python:3.9

# RUN apt install -y openssh-client git

WORKDIR /app
COPY . .

# RUN mkdir -p -m 0600 /root/.ssh

# To pull private repos from rakuten.github.com
# RUN --mount=type=secret,id=known_hosts,dst=/root/.ssh/known_hosts \
#     --mount=type=secret,id=ssh_key,dst=/root/.ssh/id_rsa \
#     ssh-keyscan -H -t rsa github.rakops.com \
#     && pip3 --no-cache-dir install -e .

CMD ["datadog_forwarder.lambda_function.lambda_handler"]
