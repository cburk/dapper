from code.src.CommandHandlers.CommandHandler import CommandHandler
from code.src.CommandHandlers.LookupBySidBase import LookupBySidBase
from code.src.queryformatter import get_add_spn_operation

class writeSPNToUserCommandHandler(CommandHandler,LookupBySidBase):
    def handle(self, command, connection, domaincomponents):
        dn = super().translate_sid_to_dc(connection, domaincomponents, command.sid)

        for spn in command.spns:
            query = get_add_spn_operation(spn)

            connection.modify(dn, query)
            print(f"Added {spn} to user {dn}/{command.sid}")


