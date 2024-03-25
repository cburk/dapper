# Some custom argument parsing methods for the shell, sure we could replace it w/ argparser eventually
# but works well enough for now
import re

def find_args(argnames, stringinput):
	indtoname = {}

	for arg in argnames:
		if arg in stringinput:
			startind = stringinput.index(arg)
			indtoname[startind] = arg
			
	keyvaluepairs = {}
	indssorted = list(indtoname.keys())
	indssorted.sort()
	i = 0
	for i in range(len(indssorted)):
		argind = indssorted[i]
		arg = indtoname[argind]

		valuestartind = argind + len(arg)
		if i + 1 == len(indssorted):
			valueendind = len(stringinput)
		else:
			valueendind = indssorted[i+1] - 1
		value = stringinput[valuestartind:valueendind]
		value = value.lstrip().rstrip()
		keyvaluepairs[arg] = value
	return keyvaluepairs

def find_args_allowduplicates(argnames, stringinput):
    indandnametuples = []
    for arg in argnames:
        for m in re.finditer(arg, stringinput):
            print(f'Found {arg} b/w {m.start()} and {m.end()}.  ind tyep: {type(m.end())}')
            indandnametuples.append((m.start(),m.end(),arg))
    sortedbystart = sorted(indandnametuples, key=lambda x: x[0])

    print(f"Sorted: {str(sortedbystart)}")
    argtoargvalues = {}
    for i in range(len(sortedbystart)):
        currentarg = sortedbystart[i]
        argtype = currentarg[2]
        argstart = currentarg[1]
        if i != len(sortedbystart) - 1:
            nextarg = sortedbystart[i + 1]
            argend = nextarg[0]
        else:
            argend = len(stringinput)
        value = stringinput[argstart:argend]
        print(f"Pre strip: {argtype}={value}")
        value = value.lstrip().rstrip()
        print(f"Post strip: {argtype}={value}")

        if argtype in argtoargvalues.keys():
            argtoargvalues[argtype].append(value)
        else:
            argtoargvalues[argtype] = [value]

    print(f"All values: {str(argtoargvalues)}")
    return argtoargvalues



