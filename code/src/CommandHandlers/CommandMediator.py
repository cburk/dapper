from code.src.CommandHandlers.WriteMsDSAllowedToActOnBehalfOfOtherIdentityHandler import writeMsDSAllowedToActOnBehalfOfOtherIdentityHandler
from code.src.CommandHandlers.WriteUacFlagsHandler import writeUacFlagsHandler
from code.src.CommandHandlers.writeSPNToUserCommandHandler import writeSPNToUserCommandHandler
from code.src.CommandHandlers.writeUserToGroupCommandHandler import writeUserToGroupCommandHandler
from code.src.CommandHandlers.writeMsDSAllowedToDelegateToCommandHandler import writeMsDSAllowedToDelegateToCommandHandler

class CommandMediator():
    def __init__(self):
        # TODO: Some form of reflection w/ strong types for handler, or some 
        # way to get a type w/o instantiating?
        self.mapping = {
            "writeMsDSAllowedToActOnBehalfOfOtherIdentityCommand" : writeMsDSAllowedToActOnBehalfOfOtherIdentityHandler(),
            "writeUacFlagsCommand": writeUacFlagsHandler(),
            "writeSPNToUserCommand": writeSPNToUserCommandHandler(),
            "writeUserToGroupCommand": writeUserToGroupCommandHandler(),
            "writeMsDSAllowedToDelegateToCommand": writeMsDSAllowedToDelegateToCommandHandler()
        }

    def handle(self, command, connection, domaincomponents):
        handler = self.mapping[(type(command).__name__)]
        handler.handle(command, connection, domaincomponents)