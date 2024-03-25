from code.src.CommandHandlers.CommandHandler import CommandHandler
from code.src.CommandHandlers.LookupBySidBase import LookupBySidBase

class writeSPNToUserCommandHandler(CommandHandler,LookupBySidBase):
    def handle(self, command, connection, domaincomponents):
        dn = super().translate_sid_to_dc(connection, domaincomponents, command.sid)
