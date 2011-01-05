#!/bin/sh
KERNEL_DIR=$1

for f in include/linux/scribe_{events,api}.h; do
	${KERNEL_DIR}/scripts/unifdef -U__KERNEL__  ${KERNEL_DIR}/$f > $f
done
