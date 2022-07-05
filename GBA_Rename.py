#!/usr/bin/env python

"""Identifies and renames Gorf functions in Ghidra that only return a WRAM address.

Many functions in Gorf exist only to return the address of a global variable
in WRAM. To ease the process of identifying these functions, this script
automatically identifies and renames these functions in the format
"returns_addr_<x>", where "<x>" is the address in WRAM. Thus, these functions
become easier to understand at first glance, and one can more easily connect
global variables/functions with changes in the state of the game. As a
result, it becomes much easier to alter the game, such as by giving yourself
infinite lives or skipping to later levels.

Gorf ROM source: https://emulationking.com/gorf/
Gorf uses ARM v4t little-endian assembly.

This script is influenced and aided by the boilerplate and flat API code found
at:
https://github.com/HackOvert/GhidraSnippets
"""

from binascii import hexlify
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SymbolUtilities


def getSymbolAddress(symbolName):
    """Returns the memory address of a given Ghidra symbol.

    Used in this script for getting the addresses of pointer labels.
    """
    # Pull symbol object from program
    symbol = SymbolUtilities.getLabelOrFunctionSymbol(currentProgram, symbolName, None)
    if (symbol != None):
        return symbol.getAddress()
    else:   # throw error if symbol wasn't found
        raise("Failed to locate label: {}".format(symbolName))


def tohex(val, nbits):
    """Converts val (a decimal integer) to an n-bit hex number.

    Used in this script for 8-bit hex values.
    Source: https://stackoverflow.com/questions/7822956/how-to-convert-negative-integer-value-to-hex-in-python
    """
    return hex((val + (1 << nbits)) % (1 << nbits))


def buildHexAddr(byteArray):
    """Converts little-endian 4-element array of bytes into one hex string."""
    byte1 = tohex(byteArray[3], 8)[2:] # cut off 0x from start of each byte
    byte2 = tohex(byteArray[2], 8)[2:]
    byte3 = tohex(byteArray[1], 8)[2:]
    byte4 = tohex(byteArray[0], 8)[2:]
    hexBytes = [byte1, byte2, byte3, byte4]
    hexAddr = ""
    # Handle each byte in turn, building up the hexAddr
    for b in hexBytes:
        if len(b) == 1:  # force each byte to be 2 numbers wide
            b = "0" + b
        hexAddr += b
    return "0x" + hexAddr


def main():
    """Identifes and renames functions that only return an address in WRAM.

    Finds functions that just return the address in WRAM where a global variable
    is stored, and renames them in the format "returns_addr_<x>", where <x> is
    the WRAM address they return.
    """
    PRINT_DEBUG = False  # set to True to see full scan and editing printout

    # Set up for analysis
    listing = currentProgram.getListing()
    program = getCurrentProgram()
    ifc     = DecompInterface()
    ifc.openProgram(program)
    fm      = currentProgram.getFunctionManager()
    funcs   = fm.getFunctions(True) # True means 'forward'

    # Iterate through each function found
    for func in funcs:
        # retrieve the lines of assembly in each function
        addrSet   = func.getBody()
        codeUnits = listing.getCodeUnits(addrSet, True) # true = 'forward'

        # functions in GORP's address-return form always have 3-5 code units
        numInstr = len(list(codeUnits))

        # length 3 fxns do not point to WRAM, and thus are ignored
        # one potential extension of this script would be rename them as well
        if numInstr == 3:
            if PRINT_DEBUG:
                print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
                print("\tnumInstr:"+ str(numInstr))

        # instructions which return an address in WRAM are always 4/5 instr long
        elif numInstr == 4 or numInstr == 5:
            if PRINT_DEBUG:
                print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
                print("\tnumInstr:"+ str(numInstr))

            # Get decompiled C code
            results    = ifc.decompileFunction(func, 0, ConsoleTaskMonitor())
            decompiled = results.getDecompiledFunction().getC()

            # if "{\n  return PTR_DAT" present, then the 1st line of decompiled
            # code is a return statement -> function does nothing but return
            if "{\n  return PTR_DAT" in decompiled:
    	        # Pull the label of the pointer out of the decompiled code
                startIdx = int(decompiled.find("PTR"))
                endIdx   = int(decompiled.find(";"))

                # Only proceed if pointer was successfully found
                if (startIdx != -1 and endIdx != -1):
                    ptrStr  = decompiled[startIdx:endIdx] # extract the label
                    ptrAddr = getSymbolAddress(ptrStr)    # get the label's addr
                    addressBytes = getBytes(ptrAddr, 4)   # get the bytes at the label's addr

                    # build user-readable version of addr in hex form from bytes
                    hexAddr = buildHexAddr(addressBytes)

                    # rename function
                    newName = "returns_addr_" + hexAddr
                    func.setName(newName, ghidra.program.model.symbol.SourceType.DEFAULT)
                    print("\tNew Function Name: " + newName)

                    if PRINT_DEBUG:
                        print("\tPTR IS: " + ptrStr)
                        print("\tPTR IS AT ADDR: " + str(ptrAddr))
                        print("\tBYTES AT " + str(ptrAddr) + ": " + str(getBytes(ptrAddr, 4)))
                        print("\tCONSTRUCTED HEX ADDR:" + hexAddr)


if (__name__ == __main__):
    main()
