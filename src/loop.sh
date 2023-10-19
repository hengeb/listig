#!/bin/sh

while true; do
  /usr/bin/php /usr/src/app/run.php --keep-alive=50
  sleep 20
done
