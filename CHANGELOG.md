# RWM changelog

## 1.0 - ensign storage

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


## 0.2 - towards backups

* basic backups
* code quality ci


## 0.1 - lower decks

* s3 low-level access
* rclone_crypt
