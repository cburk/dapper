# optional debugging logging
# eventually, should use (or write) a real logging lib that supports muxing (file+stdout) + 
# logging levels and di into all these different modules, but don't want to distract from
# OSCP prep working on the code
class FileMuxLogger():
    def __init__(self, debug):
        self.debug=debug

    # Prints statement if initialized w/ debug=true
    def print_debug(self, logmessage, filedescriptor=None):
        if self.debug:
            self.print(logmessage, filedescriptor)

    # Prints regardless of whether debug=true or false
    def print(self, logmessage, filedescriptor=None):
        print(logmessage)
        if filedescriptor and filedescriptor is not None:
            self.filedescriptor.write(str(line))
