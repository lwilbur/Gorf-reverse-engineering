# Reverse Engineering Gorf
## Purpose
Gorf is a Game Boy Advance game based off Space Invaders and Galaxian, and its ROM is freely available online.  To better understand Gorf's internal workings (and potentially create cheats, such as giving the player infinite lives or skipping levels), I examined Gorf's disassembly in Ghidra.  

Many functions in Gorf exist only to return the address of a global variable in WRAM. To ease the process of identifying such functions, this script automatically identifies and renames them in the format "returns_addr_<x>", where "<x>" is the address in WRAM. Thus, these functions become understandable at first glance, and one can more easily connect global variables/functions with changes in the state of the game.

With the aid of this script, I identified the locations in WRAM where the game's score, mission number, and number of enemies can be found. More details about my findings are in the "Findings / Global Variables" section below.


## Explanation

The script functions based on my two core finding about Gorf's disassembly.  These findings are:

1. All functions which simply return an address, and do not perform any further operations, are three to five ARM instructions long.
2. All such functions which return an address specifically in WRAM (which are the target of this reverse engineering) use four to five ARM instructions to do so, and they return the address using a label of the form `PTR_DAT_...`, where `...` is the address of the label.

Thus, my script only examines functions that are 4 or 5 instructions long.  If it turns out that this filter is overly restrictive, changing a single `if` statement will include functions of other lengths.  For each of the examined functions, the script uses the decompiled C code produced by Ghidra and confirms that the function does nothing but return a `PTR_DAT_...`.  The script then extracts the `PTR_DAT_...` label from the C code, and extracts the address from that label.  At the extracted address, the script finds the WRAM address which the function returns.  Finally, the script reconstructs that WRAM address into a hex address, and renames the function in the format `returns_addr_WRAMHexAddress`.

As far as my testing shows, the script successfully identifies and renames all currently disassembled functions which  return an address in WRAM.  The script is limited, since it can't check code which hasn't yet been tagged as a function. However, the script can be rerun without issue when the user tags new functions.

The renaming proved very helpful when finding the meaning of various global variables.  By examining the new function names, I knew which addresses to check in WRAM while the game was running.  Then, by observing how those WRAM values changed along with the game state (e.g. when enemies died or the level changed), I could identify what the global variable stored at that memory address meant.

## Script

*See the file `GBA_Rename.py` to view the script in full.*

## Findings / Global Variables

1. With the help of this script, I determined that the function at `0x0843e138`, which my script renamed to `returns_addr_0x02001fc0`, returns the address of the game's current score.  The score is stored at `0x02001fc0`.
2. With the help of this script, I determined that the function at `0x0843e19c`, which my script renamed to `returns_addr_0x020020d0`, returns the address of the number of the game's current mission.  The mission number is stored at `0x020020d0`.
3. With the help of this script, I determined that the function at `0x0843e084`, which my script renamed to `returns_addr_0x02001f9c`, returns the address of the number of enemies currently on the screen.  The number of enemies is stored at `0x02001f9c`.
