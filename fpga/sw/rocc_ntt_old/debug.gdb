# Configure for slow CPU
set remotetimeout 50
set mem inaccessible-by-default off
# Connect
target extended-remote localhost:3333

# Reset and halt
monitor reset halt

monitor riscv dmi_write 0x16 0x00000700

# Load program
load

# Set breakpoints
break main
break test_arithmetic
# Run
continue

