argon2s concept
===============

argon2d with the introduction of sha3-512 to fill the first blocks and also during the finalize routine.

uses a modified argon2 core (https://github.com/P-H-C/phc-winner-argon2), as well as the single-file sha3 implementation from libethash (https://github.com/ethereum/ethash).
