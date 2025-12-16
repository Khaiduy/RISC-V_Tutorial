##############################################
# Connection & Basic Setup
##############################################

set remotetimeout 100
set mem inaccessible-by-default off

echo "Connecting to OpenOCD...\n"
target extended-remote localhost:3333

# Check OpenOCD connection
monitor version
monitor echo "OpenOCD connected.\n"

##############################################
# Reset + Halt
##############################################

echo "Resetting and halting CPU...\n"
monitor reset halt

##############################################
# System Information
##############################################

echo "\n---- CPU Registers ----\n"
info registers

##############################################
# Load Program
##############################################

echo "\nLoading ELF...\n"
load

##############################################
# Breakpoints Information
##############################################

echo "\n---- Active Breakpoints ----\n"
info breakpoints

echo "\nSetting User Breakpoints...\n"
break main

echo "Done.\n"

##############################################
# Watchpoints (print if exist)
##############################################

echo "\n---- Active Watchpoints ----\n"
info watchpoints

##############################################
# Disassembly Around PC
##############################################

echo "\n---- Disassembly around PC ----\n"
x/20i $pc

##############################################
# Backtrace
##############################################

echo "\n---- Backtrace ----\n"
backtrace

##############################################
# Run Program
##############################################

echo "\nRunning program...\n"
continue

