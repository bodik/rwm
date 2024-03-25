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
