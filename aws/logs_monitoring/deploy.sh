#!/bin/bash

FUNCTION_NAME=$1
IMAGE_URI=$2

deploy() {
	aws lambda update-function-code \
        --function-name $FUNCTION_NAME \
        --image-uri $IMAGE_URI
}

get_status() {
    status=$(aws lambda get-function \
        --function-name $FUNCTION_NAME \
        --query Configuration.LastUpdateStatus)
}

deploy
get_status

while [ $status != '"Successful"' ]
do
    echo $status
    sleep 1
    get_status
done

echo $status
