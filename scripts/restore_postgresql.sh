#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <tar_file>"
    exit 1
fi

tar_file="$1"

if [ ! -f "$tar_file" ]; then
    echo "Error: '$tar_file' does not exist."
    exit 1
fi

temp_dir=$(mktemp -d)

tar -xzf "$tar_file" -C "$temp_dir"

sql_files=$(find "$temp_dir" -type f -name '*.sql.gz')

for dump_file in $sql_files; do
    db_name=$(basename "$dump_file" .sql.gz)
    
    createdb "$db_name"

    gunzip -c "$dump_file" | psql -q -d "$db_name"
done

rm -rf "$temp_dir"

echo "Databases restored."
