# Pattern Scanner
Referenced in https://gamehacking.academy/lesson/7/2.

A pattern scanner that will search a running Wesnoth process for the bytes 0x29 42 04. These bytes are the opcode for the sub instruction that is responsible for subtracting gold from a player when recruiting a unit.

The scanner works by using CreateToolhelp32Snapshot to find the Wesnoth process and the main Wesnoth module. Once located, a buffer is created and the module's memory is read into that buffer. The module's memory mainly contains opcodes for instruction. Once loaded, we loop through all the bytes in the buffer and search for our pattern. Once found, we print the offset.
