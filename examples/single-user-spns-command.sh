#! /bin/bash

python ldap-enumerator.py -hostip 1.2.3.4 -username 'WINDOMAIN\user' -password pass -command "enum_spns" -commandargs "-user --outfile tesout2.test"
