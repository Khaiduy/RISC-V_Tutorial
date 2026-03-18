import re
with open('Makefile', 'r') as f:
    text = f.read()

# Make sure we have proper targets for m0, m1, m2
targets = ""
for m in [0, 1, 2, 3]:
    targets += f"""
edhoc_m{m}_initiator:
\t@echo "Building EDHOC Method {m} Initiator with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
\t@$(MAKE) -C $(M3_EDHOC_LIB) clean
\t@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
\t@echo "Building Method {m} initiator (Suite $(CRYPTO_SUITE))..."
\t@$(MAKE) all TARGET=edhoc_m{m}_initiator \\
\t\tC_SOURCES="src/edhoc_initiator_m{m}.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC)" \\
\t\tASM_SOURCES="src/crt0.S" \\
\t\tINCLUDES="$(INCLUDES) $(M3_INCLUDES)"

edhoc_m{m}_responder:
\t@echo "Building EDHOC Method {m} Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
\t@$(MAKE) -C $(M3_EDHOC_LIB) clean
\t@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
\t@echo "Building Method {m} responder (Suite $(CRYPTO_SUITE))..."
\t@$(MAKE) all TARGET=edhoc_m{m}_responder \\
\t\tC_SOURCES="src/edhoc_responder_m{m}.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC)" \\
\t\tASM_SOURCES="src/crt0.S" \\
\t\tINCLUDES="$(INCLUDES) $(M3_INCLUDES)"
"""

# Let's replace anything from edhoc_m3_initiator onwards with our clean generated targets
new_text = re.sub(r'edhoc_m3_initiator:.*', targets.strip() + '\n\ndebug_make:\n\t@echo $(C_SOURCES)\n', text, flags=re.DOTALL)

with open('Makefile', 'w') as f:
    f.write(new_text)

print("Make rule patched")
