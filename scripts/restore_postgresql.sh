#!/bin/bash
set -ex
umask 077

tar_file="$1"

temp_dir=$(mktemp -d)
tar xzf "$tar_file" -C "$temp_dir"
chown -R postgres "${temp_dir}"

find "$temp_dir" -type f -name '*.sql' | while read -r dump_file; do
    su -c "psql < '$dump_file'" postgres
done

rm -rf "$temp_dir"