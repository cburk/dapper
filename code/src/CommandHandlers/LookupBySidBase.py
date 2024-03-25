from code.src.queryformatter import get_object_with_sid_filter

class LookupBySidBase():
    # We use the sid as an identifier for items that we then need to translate to a distinguished name
    # for modifying.  That lookup captured here
    def translate_sid_to_dc(self,conn,dc,sid):
        print(f"Looking up dn of victim user / user written to by sid") # Debug log
        filter = get_object_with_sid_filter(sid)
        conn.search(search_base=dc,
            search_filter=filter,
            search_scope='SUBTREE',
            attributes='*')
        res = conn.response_to_json()
        formattedentries = response_properties_subset(res,["distinguishedName"])
        if len(formattedentries) == 0:
            print(f"lookup for sid {command.sid} failed") #error log
            return
        dn = formattedentries[0]["distinguishedName"]
        print(f"Found entity w/ sid {command.sid} and distinguishedName: {dn}.") # debug level
        return dn

    def lookup_by_sid(self,conn,dc,sid):
        filter = get_object_with_sid_filter(sid)
        print(f"search w/ filter {filter}") #debug level

        conn.search(search_base=dc,
            search_filter=filter,
            search_scope='SUBTREE',
            attributes='*')
		
        res = conn.response_to_json()
        return res
