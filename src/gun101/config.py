# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Configuration constants for GUN-101."""

PROTOCOL = "GUN-101"
VERSION = "2.1"
CONTAINER_VERSION = VERSION
# Argon2id parameters for key derivation.
# As of 2024, OWASP recommends:
#   - Memory cost: at least 64 MB, but 256 MB is recommended for high security.
#   - Time cost: at least 3 iterations, but 4 is common.
#   - Parallelism: at least 4 lanes.
# We use:
#   - Time cost: 4 iterations
#   - Memory cost: 262144 KB (256 MB)
#   - Parallelism: 4 lanes
#   - Hash length: 32 bytes (256 bits)
#   - Salt length: 32 bytes
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 262144   # 256 MB expressed in KB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 32
AES_NONCE_LEN = 12
AES_KEY_LEN = 32
KEYFILE_LEN = 32
DEFAULT_CHUNK_SIZE = 64 * 1024

# Password policy (enforced during encryption, displayed by `info`).
PASSWORD_MIN_LENGTH = 10
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_DIGIT = True
PASSWORD_REQUIRE_SPECIAL = True
