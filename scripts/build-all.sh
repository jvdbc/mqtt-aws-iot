#!/usr/bin/env bash
# See https://github.com/golang/go/wiki/GoArm

PROJECT_PATH=$(dirname $( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd ))
CMD_PATH=${PROJECT_PATH}/cmd
BUILD_PATH=${PROJECT_PATH}/build
PLATFORMS=("windows/amd64" "linux/amd64")
# PLATFORMS=("windows/amd64" "linux/amd64" "linux/arm/7")

for platform in "${PLATFORMS[@]}"
do
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}
    DIRNAME="${GOOS}/${GOARCH}"
    
    if [[ ${#platform_split[@]} -gt 2 ]]; then
        GOARM=${platform_split[2]}
        DIRNAME=${DIRNAME}/${GOARM}
        export GOARM=${GOARM}
    fi

	export GOOS=${GOOS} GOARCH=${GOARCH}
    for f in ${CMD_PATH}/*; do
        if [ -d "$f" ]; then
            cd "${f}"
            mkdir -p ${BUILD_PATH}/${DIRNAME}
            # TODO debug option in param
            go build -gcflags=all="-N -l" -o ${BUILD_PATH}/${DIRNAME} .
            if [ $? -ne 0 ]; then
                echo 'An error has occurred! Aborting the script execution...'
                exit 1
            fi
        fi
    done
done