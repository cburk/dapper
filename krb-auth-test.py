

from ldap3 import Server, Connection, Tls, SASL, KERBEROS
import ssl
tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
server = Server('ldap://dc.windomain.local', use_ssl=True, tls=tls)
# TODO: Prefix w/ ldaps or ldap? 
# Prefix seems necessary here
# TODO: Specify user? Do we need TGS for particular host w/ particular service type?
c = Connection(
    server, authentication=SASL, sasl_mechanism=KERBEROS)
c.bind()
print(c.extend.standard.who_am_i())
