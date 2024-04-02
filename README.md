# RWM - Restic WORM Manager

## The story

Restic is a fast and secure backup program. Uses client-storage architecture to backup
local filesystem to the variety of backends including local and remote storages such
as S3. Given it's server-less nature, a backed-up resource has ability to manipulate it's
backup storage. In case of server compromise a ransomware attacker is able to wipe out
all backups.

S3 can ensure safety of all data ever put in the bucket with WORM (Object Locking)
capabilities, such any object is immutable for it's configurable "lifetime", any update
is stored as a version of the bucket object. Permissions to manipulate the objects and
versions are subjected to access policies and can be delegated to access_keys/users
with fine granularity.

RWM facilitates standard restic backup process, that for every successfull backup generates
list of current contents of used S3 bucket, recording all current objects and their latest
versions. RWM bucket state data can be later used to reconstruct state of the bucket for
any saved point-in-time defeating possible deletion of the data in most recent versions of
the protected bucket objects.

Using WORM protection makes the bucket contents ever-increasing in size. RWM workflow allows to
check current state of the backup, and if found complete and correct, drop all non-latest
versions of the bucket objects reclaiming free space on the underlying storage. This operation
must be delegated to secure element residing outside of attacker's reach and would use privileged
credentials for the managed bucket.


## Features

* low-level S3 access for aws cli and rclone
* rclone "crypt over S3" backend
* restic with S3 repository
* simple backup manager/executor
* storage manager
  * create, delete and list policed storage buckets
  * check if used bucket is configured with expected policies
  * drop all versions to reclaim storage space

TODO:
* generate and store current bucket state state-data
* recreate bucket contents on local filesystem (or remote bucket) acording to specified
  state data
* ??? check completeness of the current state of the bucket
* unlike in other backup solutions, attacker with credentials can restore
  old data from the repository/bucket, this should be discussed (howto threat modeling ?)


## Usage

### Install
```
git clone git@gitlab.cesnet.cz:radoslav_bodo/rwm.git /opt/rwm
cd /opt/rwm
make install
```


### RWM: simple backups

Backups follows standard restic procedures, but adds profile like configuration
to easily run in schedulers.

```
cp examples/rwm-backups.conf rwm.conf
rwm restic init

rwm backup_all
rwm restic snapshots
rwm restic mount /mnt/restore
```


### RWM: backups with policed buckets

Two distinct S3 accounts required (*admin*, *user1*)

```
cp examples/rwm-admin.conf admin.conf
rwm --confg admin.conf create_storage bucket1 user1
rwm --confg admin.conf storage_check_policy bucket1
rwm --confg admin.conf storage_list

cp examples/rwm-backups.conf rwm.conf
rwm restic init
rwm storage_check_policy bucket1

rwm backup_all
rwm restic snapshots
rwm restic mount /mnt/restore

# if current storage state is consistent, one can drop old object versions from time to time to reclaim storage space
rwm --confg admin.conf storage_drop_versions bucket1
```


### Other usages

#### AWS cli

```
cp examples/rwm-rclone.conf rwm.conf
rwm aws s3 ls s3://
rwm aws s3api list-buckets
rwm rclone lsd rwmbe:/
```

#### rclone with crypt overlay

rclone_crypt defines single default remote named "rwmbe:/" pointed to `rwm_rclone_crypt_bucket` path.

```
cp examples/rwm-rclone.conf rwm.conf
rwm rclone_crypt sync /data rwmbe:/
rwm rclone_crypt lsl rwmbe:/
```

#### Restic: manual restic backup

```
cp examples/rwm-restic.conf rwm.conf
rwm restic init
rwm restic backup /data
rwm restic snapshots
rwm restic mount /mnt/restore
```


## Notes

* executed tools stdout is buffered, eg. `restic mount` does not print immediate output as normal
* passthrough full arguments to underlying tool with "--" (eg. `rwm rclone -- ls --help`).
* runner microceph breaks on reboot because of symlink at /etc/ceph


## Development
```
git clone git@gitlab.cesnet.cz:radoslav_bodo/rwm.git /opt/rwm
cd /opt/rwm
make install
make install-dev
make microceph-service
. venv/bin/activate
make coverage lint
```


## Gitlab Runner

```
git clone git@gitlab.cesnet.cz:radoslav_bodo/rwm.git /opt/rwm
cd /opt/rwm
export RUNNER_URL=
export RUNNER_TOKEN=
make runner
```


## References

* https://restic.readthedocs.io/
* https://github.com/CESNET/aws-plugin-bucket-policy
* https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
* https://aws.amazon.com/blogs/storage/point-in-time-restore-for-amazon-s3-buckets/
