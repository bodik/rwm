# RWM - Restic WORM Manager

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

RWM can:

* check if used bucket is configured for versioning

* check if used access_key does not have administrator privileges to manipulate
  with WORM policies

* generate and store current bucket state state-data

* recreate bucket contents on local filesystem (or remote bucket) acording to specified
  state data

* ??? check completeness of the current state of the bucket

* prune all non-recent object versions to reclaim storage space


TBD:
* unlike in other backup solutions, attacker with credentials can restore any old data from the repository/bucket
* number of object files vs size


## Usage

Beside the WORM management features, `rwm` can also be used as simple wrapper to other S3 related
tools such as `aws` CLI, `rclone` and `restic`.

It can be also used as simple backup manager for intended usecases.


### Install
```
git clone git@gitlab.flab.cesnet.cz:bodik/rwm.git /opt/rwm
cd /opt/rwm
make install
```

### Simple copy: rclone with crypt overlay

```
cat > rwm.conf <<__EOF__
rwm_s3_endpoint_url: ""
rwm_s3_access_key: ""
rwm_s3_secret_key: ""
rwm_rclone_crypt_bucket: "rwmcrypt"
rwm_rclone_crypt_password: ""
__EOF__

rwm rclone_crypt sync /data rwmbe:/
rwm rclone_crypt lsl rwmbe:/
```

### Restic: manual restic backup

```
cat > rwm.conf <<__EOF__
rwm_s3_endpoint_url: ""
rwm_s3_access_key: ""
rwm_s3_secret_key: ""
rwm_restic_bucket: "rwmrestic"
rwm_restic_password: ""
__EOF__

rwm restic init
rwm restic backup /data
rwm restic snapshots
```

### RWM: simple backups

```
cat > rwm.conf <<__EOF__
rwm_s3_endpoint_url: ""
rwm_s3_access_key: ""
rwm_s3_secret_key: ""

rwm_restic_bucket: "rwmrestic"
rwm_restic_password: ""

rwm_backups:
  backup1:
    filesdirs:
      - /etc
      - /data
    excludes:
      - *.cache
    extras:
      - --tag
      - mytag1

rwm_retention:
  keep-daily: "14"
  keep-weekly: "20"
__EOF__

rwm backup_all
```


## Notes

#### Development
```
git clone git@gitlab.flab.cesnet.cz:bodik/rwm.git /opt/rwm
cd /opt/rwm
make install
make venv
. venv/bin/activate
```


### Passing arguments

Passthrough full arguments to underlyin tool with "--" (eg. `rwm rclone -- ls --help`).


### rclone sync
* https://rclone.org/commands/rclone_sync/

It is always the contents of the directory that is synced, not the directory itself.
So when source:path is a directory, it's the contents of source:path that are copied,
not the directory name and contents. See extended explanation in the copy command if unsure.


### rclone crypt

* corect, fails to download corrupted files
```
2024/03/23 16:54:31 ERROR : testfile.txt: Failed to copy: failed to open source object: not an encrypted file - bad magic string
2024/03/23 16:54:31 ERROR : Attempt 1/3 failed with 1 errors and: failed to open source object: not an encrypted file - bad magic string
```

* corect, skips bad filenames
```
2024/03/23 16:53:56 DEBUG : 6p78fe3tlp5o7ngi241jsjl2qX: Skipping undecryptable file name: illegal base32 data at input byte 25
```