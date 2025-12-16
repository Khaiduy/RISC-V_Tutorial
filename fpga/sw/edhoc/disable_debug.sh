#!/bin/bash
# Script to comment out debug printing in EDHOC PSK implementation
# Preserves error handling but removes verbose logging

cd /home/khaiduy/Workspace/RISC-V_Tutorial/fpga/sw/edhoc/uoscore-uedhoc-psk/src

# Function to comment out debug lines in a file
comment_debug() {
    local file="$1"
    
    # Create backup
    cp "$file" "$file.bak"
    
    # Comment out print_hex calls
    sed -i 's/^\(\s*\)print_hex(/\1\/\/ print_hex(/g' "$file"
    
    # Comment out PRINT_ARRAY calls (except in error contexts)
    sed -i '/\[ERROR\]/!s/^\(\s*\)PRINT_ARRAY(/\1\/\/ PRINT_ARRAY(/g' "$file"
    
    # Comment out kprintf debug lines (keep ERROR lines)
    sed -i '/\[ERROR\]/!s/^\(\s*\)kprintf("\[/\1\/\/ kprintf("[/g' "$file"
    sed -i '/\[ERROR\]/!s/^\(\s*\)kprintf("\\r\\n==/\1\/\/ kprintf("\\r\\n==/g' "$file"
    sed -i '/\[ERROR\]/!s/^\(\s*\)kprintf("==/\1\/\/ kprintf("==/g' "$file"
    
    # Comment out specific verbose patterns
    sed -i 's/^\(\s*\)\/\/ kprintf("\[CIPHER\]/\1\/\/ kprintf("[CIPHER]/g' "$file"
    sed -i 's/^\(\s*\)\/\/ kprintf("\[PSK/\1\/\/ kprintf("[PSK/g' "$file"
    sed -i 's/^\(\s*\)\/\/ kprintf("\[PRK/\1\/\/ kprintf("[PRK/g' "$file"
    sed -i 's/^\(\s*\)\/\/ kprintf("\[TH/\1\/\/ kprintf("[TH/g' "$file"
    sed -i 's/^\(\s*\)\/\/ kprintf("\[I-/\1\/\/ kprintf("[I-/g' "$file"
    sed -i 's/^\(\s*\)\/\/ kprintf("\[R-/\1\/\/ kprintf("[R-/g' "$file"
    sed -i 's/^\(\s*\)\/\/ kprintf("\[CRYPTO/\1\/\/ kprintf("[CRYPTO/g' "$file"
    sed -i 's/^\(\s*\)\/\/ kprintf("\[TIMING/\1\/\/ kprintf("[TIMING/g' "$file"
}

# Process all C files
find . -name "*.c" -type f | while read file; do
    echo "Processing $file..."
    comment_debug "$file"
done

echo "Debug printing disabled. Backups saved with .bak extension"
echo "To restore: find . -name '*.bak' -exec bash -c 'mv \"\$0\" \"\${0%.bak}\"' {} \;"
