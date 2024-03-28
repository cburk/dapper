from code.src.CommandHandlers.CommandHandler import CommandHandler
from code.src.CommandHandlers.LookupBySidBase import LookupBySidBase
from code.src.queryformatter import get_add_user_to_group_operation

class writeUserToGroupCommandHandler(CommandHandler,LookupBySidBase):
    def handle(self, command, connection, domaincomponents):
        print(f'Add {command.usersid} to {command.groupsid}') # Debug log

        user = super().translate_sid_to_dc(connection, domaincomponents, command.usersid)
        group = super().translate_sid_to_dc(connection, domaincomponents, command.groupsid)

        operation = get_add_user_to_group_operation(user)
        connection.modify(group,operation)

        print(f'Wrote successfully')