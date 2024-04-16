#!/bin/sh
# release helper

REGISTRY_URL="gitlab-registry.cesnet.cz"
IMAGE_NAME="radoslav_bodo/rwm"

BRANCH=$(git symbolic-ref -q --short HEAD || git describe --tags --exact-match)
if [ -z "$BRANCH" ]; then
    echo "Error: Unable to determine current branch."
    exit 1
fi

case "$1" in
    login)
        docker login "$REGISTRY_URL"
    ;;

    build)
        docker build -t "${REGISTRY_URL}/${IMAGE_NAME}:${BRANCH}" .
    ;;

    push)
	    docker push "${REGISTRY_URL}/${IMAGE_NAME}:${BRANCH}"
    ;;

    pull)
        docker image pull "${REGISTRY_URL}/${IMAGE_NAME}:${BRANCH}"
    ;;

    run)
        shift
        docker run --rm -h "$(hostname)" -v "$(pwd)/rwm.conf:/opt/rwm/rwm.conf" -it "${REGISTRY_URL}/${IMAGE_NAME}:${BRANCH}" "$@"
    ;;

    *)
        echo "invalid command"
        exit 1
    ;;
esac