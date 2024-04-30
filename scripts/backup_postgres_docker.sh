#!/bin/bash
# example dockerized backup of dockerized postgresql

set -e
umask 077

# note: Alternatively, this can be placed in the rwm backup.prerun configuration field.
docker exec -u postgres pgdocker pg_dumpall --clean > /var/backups/pgdocker.sql

docker run \
    --rm \
    --pull always \
    --volume "/etc/rwm.conf:/opt/rwm/rwm.conf:ro" \
    --volume "/var/backups:/var/backups" \
    --volume "/var/run:/var/run" \
    --hostname "pgdocker-rwm-container" \
    "gitlab-registry.cesnet.cz/radoslav_bodo/rwm:release-1.1" \
    backup pgdocker

# note: dtto
rm -f /var/backups/pgdocker.sql