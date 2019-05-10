#!/bin/bash

echo "Updating events.bif.bro..."

sed -i -e 's/^export.*{//g' ../build/lib/bif/events.bif.bro

TFILE=../build/lib/bif/fixup_events.bif.bro$$
echo "export { " >>$TFILE
cat ../src/bro.init >>$TFILE
cat ../build/lib/bif/events.bif.bro >>$TFILE
mv $TFILE ../build/lib/bif/events.bif.bro

(cd $1 && $2/bro-plugin-create-package.sh Bro_MQTT)
