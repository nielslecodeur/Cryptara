package main

import "base:runtime"
import "core:strings"

word_list_data := string(#load("../data/words.txt"))

load_word_list :: proc() -> ([2048]string, bool) {
	context = runtime.default_context()

	lines := strings.split_lines(word_list_data)

	words: [2048]string
	count := 0

	for line in lines {
		if strings.trim_space(line) == "" {
			continue
		}

		if count >= 2048 {
			return {}, false
		}

		words[count] = line
		count += 1
	}

	if count != 2048 {
		return {}, false
	}

	return words, true
}

get_bytes :: proc(entropy: ^[16]u8) -> (bytes: [17]u8) {
	hash := sha256(entropy[:])

	copy(bytes[0:16], entropy[:])
	bytes[16] = hash[0] & 0xF0

	return bytes
}

get_indexes :: proc(bytes: ^[17]u8) -> (indexes: [12]u16) {
	for &v, i in indexes {
		bit_offset := i * 11
		value: u16 = 0

		for j in 0 ..< 11 {
			bit_index := bit_offset + j
			byte_index := bit_index / 8
			bit_in_byte := 7 - (bit_index % 8)
			bit := (bytes[byte_index] >> u8(bit_in_byte)) & 1

			value = (value << 1) | u16(bit)
		}

		v = value
	}

	return indexes
}
