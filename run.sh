#!/bin/sh
echo -e "############################################################################\n"
echo -e "In order for this to work, this is required to run in root. If you have not"
echo -e "set a password for root yet do so now with this command.\n"
echo -e "$ sudo passwd root \n"
echo -e "############################################################################\n"
read -p "Press Enter to continue "
su -c ./main.sh root