# RWM changelog

## 1.1 - Brahms tuning

* added: storage-state command
* added: config autotags (add restic snapshot tag with config name of the backup)
* added: config backup_extras (adds arguments for all restic backups; eg. global pack-size)
* changed: use paging, bulk operations and client api for storage-delete and storage-drop-versions
* changed: radosgw-admin path resolution, allow to run tests on any ceph installation
* changed: minor output tweaks
* fixed: storage-delete for large buckets


## 1.0 - Ensign Storage

* added: storage management
* added: restic tags to backup config
* added: prerun, postrun phases for backups
* added: basic docker image (NAS backups from within the NAS itself use-case)
* added: parallel execution lock for rwm backups
* added: config validation and reference documentation
* added: cron helper
* added: warnings on used buycket policy and config file permissions
* added: licence
* added: mysql backup script
* added: microceph service for development environment
* changed: gitlab runner playbook file placement
* changed: command name separator from underscore to dash
* removed: rclone use-cases


## 0.2 - Towards backups

* basic backups
* code quality ci


## 0.1 - Lower decks

* s3 low-level access
* rclone_crypt
