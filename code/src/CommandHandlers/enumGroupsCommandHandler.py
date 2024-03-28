from code.src.queryformatter import get_groups_filter
from code.src.CommandHandlers.CommandHandler import CommandHandler

class enumGroupsCommandHandler(CommandHandler):
    def handle(self, command, connection, domaincomponents):
        query = get_groups_filter(command.like)
        connection.search(search_base=domaincomponents,
            search_filter=query,
            search_scope='SUBTREE',
            attributes='*')

        res = connection.response_to_json()

        return res