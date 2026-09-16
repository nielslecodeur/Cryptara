package main

import "base:runtime"
import "core:strings"

@(export)
get_bytes_ptr :: proc "c" (out: rawptr) {
	context = runtime.default_context()

	entropy := generate_entropy()
	bytes := get_bytes(&entropy)

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
