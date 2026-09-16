package main

import "base:runtime"
import "core:strings"

@(export)
get_bytes_ptr :: proc "c" (out: rawptr) {
	context = runtime.default_context()

	entropy := generate_entropy()
	bytes := get_bytes(&entropy)

	bytes[16] &= 0xF0

	dst := cast(^[17]u8)out
	dst^ = bytes
}

@(export)
get_words :: proc "c" (bytes: rawptr, out: rawptr) -> bool {
	context = runtime.default_context()

	words, ok := load_word_list()

	if !ok {
		return false
	}

	data := cast(^[17]u8)bytes
	indexes := get_indexes(data)

	result := cast(^[12]cstring)out

	for i := 0; i < 12; i += 1 {
		word_index := indexes[i]

		if word_index >= 2048 {
			return false
		}

		result^[i] = strings.clone_to_cstring(words[word_index])
	}

	return true
}


@(export)
get_bytes_from_words :: proc "c" (words_ptr: rawptr, out: rawptr) -> bool {
	context = runtime.default_context()

	words_list, ok := load_word_list()

	if !ok {
		return false
	}

	words := cast(^[12]cstring)words_ptr
	result := cast(^[17]u8)out

	for i := 0; i < 17; i += 1 {
		result^[i] = 0
	}

	for i := 0; i < 12; i += 1 {
		word := words^[i]

		word_index := -1

		for j := 0; j < 2048; j += 1 {
			if string(word) == words_list[j] {
				word_index = j
				break
			}
		}

		if word_index < 0 {
			return false
		}

		for j := 0; j < 11; j += 1 {
			bit_position := i * 11 + j
			byte_index := bit_position / 8
			bit_in_byte := 7 - (bit_position % 8)

			shift := u32(10 - j)
			bit := (u32(word_index) >> shift) & 1

			result^[byte_index] |= u8(bit) << u8(bit_in_byte)
		}
	}

	return true
}
