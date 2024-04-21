#!/bin/bash
# toggle aslr on/off

randomva="/proc/sys/kernel/randomize_va_space"
if [[ "$(cat $randomva)" == "2" ]]; then
  echo 0 > $randomva
  echo "ASLR is now OFF!"
else
  echo 2 > $randomva
  echo "ASLR is now ON!"
fi
