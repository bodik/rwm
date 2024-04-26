#!/bin/sh
# usage:
# 12 1 * * * /bin/sh /opt/rwm/scripts/cron.sh

umask 077
LOGFILE="/var/log/rwm/cron.log.$(date +'%Y-%m-%dT%H:%M:%S%z')"
mkdir -p "$(dirname "$LOGFILE")"

/opt/rwm/rwm.py --config /etc/rwm.conf backup-all 1>"$LOGFILE" 2>&1
RET=$?

if [ $RET = 0 ]; then
	RESULT="OK"
else
	RESULT="ERROR"
fi
# shellcheck disable=SC2002
cat "$LOGFILE" | mail -E -s "rwm backup-all $RESULT" "$LOGNAME"

find /var/log/rwm -type f -mtime +90 -exec rm {} \;

exit $RET