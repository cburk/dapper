#! /bin/bash

# Ex. usage:
# ./single.sh enum_password_settings
# ./single.sh enum_spns -user
# ./single.sh enum_spns -user --outfile tesout.test

cmd=$1
argsarr=("$@")
cmdargs="${argsarr[@]:1}"

#python ldap-enumerator.py -ldaphost 192.168.194.203 -username 'WINDOMAIN\vagrant' -password vagrant -command $cmd -commandargs="-user"
python ldap-enumerator.py -ldaphost 192.168.194.203 -username 'WINDOMAIN\vagrant' -password vagrant -command "$cmd" -commandargs="$cmdargs"
