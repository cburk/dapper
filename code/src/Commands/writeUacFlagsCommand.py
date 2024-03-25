# TODO: Lets user modify arbitrary UAC flags (on or off), by name or by 
# command should probably take just one version (human readable?), but maybe display all options in the help?

class writeUacFlagsCommand():
    def __init__(self, sid, flagsToSet, flagsToUnset):
        self.sid = sid
        self.flagsToSet = flagsToSet
        self.flagsToUnset = flagsToUnset
