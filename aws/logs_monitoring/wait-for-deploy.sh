#!/bin/bash

FUNCTION_NAME=$1

get_status() {
    status=$(aws lambda get-function \
        --function-name $FUNCTION_NAME \
        --query Configuration.LastUpdateStatus)
}

get_status

while [ $status != '"Successful"' ]
do
    echo $status
    sleep 1
    get_status
done

echo $status
