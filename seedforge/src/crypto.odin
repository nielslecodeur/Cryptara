package main

import "core:crypto/sha2"
import "core:math/rand"

generate_entropy :: proc() -> (entropy: [16]u8) {
	return transmute([16]u8)rand.uint128()
}

sha256 :: proc(input: []u8) -> (digest: [sha2.DIGEST_SIZE_256]u8) {
	ctx: sha2.Context_256

	sha2.init_256(&ctx)
	sha2.update(&ctx, input)
	sha2.final(&ctx, digest[:])

	return digest
}
