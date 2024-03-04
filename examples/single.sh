#! /bin/bash

# Ex. usage:
# ./single.sh enum_password_settings
# ./single.sh enum_spns -user
# ./single.sh enum_spns -user --outfile tesout.test

cmd=$1
argsarr=("$@")
cmdargs="${argsarr[@]:1}"

python ../ldap-enumerator.py -ldaphost 1.2.3.4 -username 'WINDOMAIN\user' -password pass -command "$cmd" -commandargs="$cmdargs"
