#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	// all of your C code here
	
	// data = ptr to data, size = size of data, start_address = print the address starting from this value
	void hexdump(const void* data, size_t size, size_t start_address);

#ifdef __cplusplus
}
#endif