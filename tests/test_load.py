# Verify the '.text' section is loaded
assert('.text' in [b.name for b in getMemoryBlocks()])

# Verify the entry point has been marked
entry = None
for f in currentProgram.getFunctionManager().getFunctions(True):
  if f.name == 'entry':
    entry = f
    break
assert(entry is not None)

# Attempt to decompile the entry point function
from ghidra.app.decompiler import DecompInterface
di = DecompInterface()
di.openProgram(currentProgram)
print(di.decompileFunction(entry, 0, None).getDecompiledFunction().getC())

# Ghidra silently swallows exceptions, so create a file at the end of the test
# to mark success
open('TEST_PASS', 'w').write('pass')
