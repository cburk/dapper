from code.src.CommandHandlers.CommandHandler import CommandHandler
from code.src.CommandHandlers.LookupBySidBase import LookupBySidBase
from code.src.queryformatter import UAC_FLAG_DESCRS_TO_FLAGS, get_set_uac_operation, uac_bitstring_to_flags, response_properties_subset

class writeUacFlagsHandler(CommandHandler,LookupBySidBase):
    def unset_flag(self, uac, flag):
        return uac & (~flag)

    def set_flag(self, uac, flag):
        return uac | flag

    def handle(self, command, connection, domaincomponents):
        # Translate strs => ints
        translatedsets = [UAC_FLAG_DESCRS_TO_FLAGS[x] for x in command.flagsToSet if x in UAC_FLAG_DESCRS_TO_FLAGS.keys()]
        if len(translatedsets) != len(command.flagsToSet):
            print(f"Error: encountered unkown flag(s): {str([x for x in command.flagsToSet if not x in UAC_FLAG_DESCRS_TO_FLAGS])}") # Error log
            return
        translatedunsets = [UAC_FLAG_DESCRS_TO_FLAGS[x] for x in command.flagsToUnset if x in UAC_FLAG_DESCRS_TO_FLAGS.keys()]
        if len(translatedunsets) != len(command.flagsToUnset):
            print(f"Error: encountered unkown flag(s): {str([x for x in command.flagsToUnset if not x in UAC_FLAG_DESCRS_TO_FLAGS])}") # Error log
            return

        # Update
        user = super().lookup_by_sid(connection, domaincomponents, command.sid)
        formattedentries = response_properties_subset(user,["distinguishedName","userAccountControl"])
        if len(formattedentries) == 0:
            print(f"lookup for sid {sid} failed") #error log
            return
        dn = formattedentries[0]["distinguishedName"]
        olduac = formattedentries[0]["userAccountControl"]

        newuac = olduac
        for unsetflag in translatedunsets:
            newuac = self.unset_flag(newuac, unsetflag)
        for setflag in translatedsets:
            newuac = self.set_flag(newuac, setflag)

        updateUacFlagsCommand = get_set_uac_operation(newuac)
        connection.modify(dn,updateUacFlagsCommand)

        print(f"Updated uac for {dn}:") # normal level log?
        print(f"Original: {uac_bitstring_to_flags(olduac)}") # normal level log?
        print(f"Modified: {uac_bitstring_to_flags(newuac)}") # normal level log?
