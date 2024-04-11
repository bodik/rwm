# RWM - Restic WORM Manager

## The story

Restic is a fast and secure backup program that employs a client-storage
architecture to backup local filesystems to various backends, including both
local and remote storage options such as S3. Due to its server-less nature, a
backed-up resource has the capability to manipulate its backup storage.
However, in the event of a server compromise, a ransomware attacker could
potentially wipe out all backups.

S3 provides robust data protection with features like versioning and object
locking (WORM). When versioning is enabled on a bucket, any updates to objects
are stored as new versions. Access permissions for manipulating objects and
versions can be finely controlled through access policies, allowing delegation
to access keys or users with precise granularity.

RWM supports the standard restic backup process. For each backup performed, it
records the final bucket state, including all objects and their latest version
IDs. This bucket state data can then be used later to reconstruct the bucket to
any saved point-in-time, preventing potential deletion of data in the most
recent versions of the protected bucket objects.

Using versioning for protection leads to the continual growth of the bucket's
contents. When the backup storage is verified to be complete and accurate, RWM
allows for the removal of all non-latest versions of the bucket objects,
freeing up space on the underlying storage. However, this task should be
delegated to a secure entity beyond the attacker's reach and should utilize
privileged credentials for managing the bucket.


*There may be a proper WORM setup with object locking and lifecycle rules for me
somewhere - if I only knew.*


## Features

* low-level S3 access for aws cli

* performing backups
  * restic with S3 repository
  * simple backup manager/executor
    * saves bucket state during backups

* storage management
  * create, delete and list policed storage buckets
  * drop all versions to reclaim storage space
  * restore saved bucket state to new bucket


## Known issues

* During tests RGW is leaking RADOS objects (likely Ceph bug; TODO fix)

* Unlike in other backup solutions, attacker with credentials can restore
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

Two S3 accounts in the same tenant are required (*admin*, *user1*)

```
# create storage
cp examples/rwm-admin.conf admin.conf
rwm --confg admin.conf storage_list
rwm --confg admin.conf storage_create bucket1 user1

# do backups
cp examples/rwm-backups.conf rwm.conf
rwm restic init
rwm backup_all
rwm restic snapshots
rwm restic mount /mnt/restore

# if storage is consistent, drop old object versions to reclaim storage space
rwm --confg admin.conf storage_drop_versions bucket1

# if storage gets corrupted, state can be restored to other bucket
rwm --confg admin.conf storage_info bucket1  # select existing state file from here
rwm --confg admin.conf storage_restore_state bucket1 bucket1-restore rwm/state_[timestamp].json.gz
```


### Other usages

#### AWS cli

```
cp examples/rwm-restic.conf rwm.conf
rwm aws s3 ls s3://
rwm aws s3api list-buckets
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
* passthrough full arguments to underlying tool with "--" (eg. `rwm aws -- s3api --help`).
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
