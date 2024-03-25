		
        
from code.src.CommandHandlers.CommandHandler import CommandHandler
from code.src.CommandHandlers.LookupBySidBase import LookupBySidBase
from code.src.queryformatter import get_append_msds_allowedtodelegateto_operation

class writeMsDSAllowedToDelegateToCommandHandler(CommandHandler,LookupBySidBase):
    def handle(self, command, connection, domaincomponents):
        res = super().lookup_by_sid(command.sid)

        formattedentries = response_properties_subset(res,["distinguishedName","msDS-AllowedToDelegateTo"])
        if len(formattedentries) == 0:
        	print(f"lookup for sid {sid} failed") #error log
        	return
        dn = formattedentries[0]["distinguishedName"]
        print(f"Found entity w/ sid {sid} and distinguishedName: {dn}.") # debug level
        old = formattedentries[0]["msDS-AllowedToDelegateTo"]
        print(f"{sid} previous msDs-AllowedToDelegateTo: {old}.") # normal level?

        updatecommand = get_append_msds_allowedtodelegateto_operation(spn)
        connection.modify(dn,updatecommand)

        res = super().lookup_by_sid(command.sid)
        formattedentries = response_properties_subset(res,["msDS-AllowedToDelegateTo"])
        new = formattedentries[0]["msDS-AllowedToDelegateTo"]
        print(f"{sid} updated msDs-AllowedToDelegateTo: {new}.") # normal level?
