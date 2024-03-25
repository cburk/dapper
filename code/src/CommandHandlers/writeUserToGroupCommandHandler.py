from code.src.CommandHandlers.CommandHandler import CommandHandler

class writeUserToGroupCommandHandler(CommandHandler):
    def handle(self, command, connection, domaincomponents):
        dn = super().translate_sid_to_dc(connection, domaincomponents, command.sid)
