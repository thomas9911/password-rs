#! /bin/bash

(
    trap 'kill 0' SIGINT
    docker build -t password_rs_default -f Dockerfile-default . &
    docker build -t password_rs_slim -f Dockerfile-slim . &
    docker build -t password_rs_alpine -f Dockerfile-alpine . &
    wait
)

(
    trap 'kill 0' SIGINT
    docker run --rm password_rs_default &
    docker run --rm password_rs_slim &
    docker run --rm password_rs_alpine &
    wait
)
