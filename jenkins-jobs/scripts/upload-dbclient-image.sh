#!/bin/bash
IMAGE_NAME="dbclient"
TAG="latest"
OPTS=$(getopt -o d:i:r:o:t: --long dir:,image-name:,registry:,organisation:,dest-login:,dest-pass:,tag: -n 'parse-options' -- "$@")
if [ $? != 0 ] ; then echo "Failed parsing options." >&2 ; exit 1 ; fi
eval set -- "$OPTS"

while true; do
  case "$1" in
    -d | --dir )                INSTALL_SOURCE_DIR=$2;          shift; shift ;;
    -i | --image-name )         IMAGE_NAME=$2;                  shift; shift ;;
    -r | --registry )           REGISTRY=$2;                    shift; shift ;;
    -o | --organisation )       ORGANISATION=$2;                shift; shift ;;
    -t | --tag )                TAG=$2;                         shift; shift ;;
    --dest-login )              DEST_LOGIN=$2;                  shift; shift ;;
    --dest-pass )               DEST_PASS=$2;                   shift; shift ;;
    -h | --help )               PRINT_HELP=true;                shift ;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done

if [ ${PRINT_HELP} == true ]; then
  echo "TODO create help"
fi

pushd "${INSTALL_SOURCE_DIR}" || exit 1

docker login -u "${DEST_LOGIN}" -p "${DEST_PASS}" "${REGISTRY}"

docker build -t tooling ./tooling
docker build -t "${IMAGE_NAME}:${TAG}" ./db-client

target="${REGISTRY}/${ORGANISATION}/${IMAGE_NAME}:${TAG}"
docker tag "${IMAGE_NAME}" "$target"
docker push "$target"
