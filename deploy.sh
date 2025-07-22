#!/usr/bin/env bash

export SHA=$1

sed -i "s/\${SHA}/$SHA/g" compose.yaml

docker compose -f compose.yaml up --detach
echo "New version deployed with SHA: $SHA"