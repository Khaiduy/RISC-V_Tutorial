/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef PRINT_UTIL_H
#define PRINT_UTIL_H

#include <stdint.h>
#include <stdio.h>

/**
 *@brief			Prints an array for debug purposes.
 *@param[in] in_data		The array to be printed.
 *@param in_len			The length of the array.
 */
void print_array(const uint8_t *in_data, uint32_t in_len);
void print_labeled_array(const char *label, const uint8_t *in_data,
				 uint32_t in_len);

/**
 * @brief 			In case of an error this function prints where 
 * 				the error occurred.
 * 
 * @param error_code 		The error code to be printed.
 * @param file_name 		The file name where the error occurred.
 * @param line 			The line at which the error occurred.
 */
void handle_runtime_error(int error_code, const char *file_name,
			  const int line);

/**
 * @brief 			In case of an error in a function belonging to 
 * 				an external library this function prints where 
 * 				the error occurred.
 * 
 * @param error_code 		The error code to be printed.
 * @param file_name 		The file name where the error occurred.
 * @param line 			The line at which the error occurred.
 */
void handle_external_runtime_error(int error_code, const char *file_name,
				   const int line);

#ifdef DEBUG_PRINT
extern void kprintf(const char *, ...);
#define RED "\x1B[31m"
#define RESET "\033[0m"
static const char transport_deinit_message[] = {
	RESET "Transport deinitialized at %s:%d\n\n"
};
static const char runtime_error_message[] = {
	RED "Runtime error: code %d at %s:%d\n\n" RESET
};
static const char external_runtime_error_message[] = {
	RED "External lib runtime error: code %d at %s:%d\n\n" RESET
};

#define PRINT_ARRAY(msg, a, a_len)                                             \
	do {                                                                     \
		print_labeled_array((msg), (a), (a_len));                         \
	} while (0)
#define PRINT_MSG(msg)                                                         \
	do {                                                                     \
		kprintf("%s", (msg));                                             \
	} while (0)
#define PRINTF(f_, ...)                                                        \
	do {                                                                     \
		kprintf((f_), ##__VA_ARGS__);                                       \
	} while (0)
#else
#define PRINT_ARRAY(msg, a, a_len)                                             \
	do {                                                                     \
	} while (0)
#define PRINT_MSG(msg)                                                         \
	do {                                                                     \
	} while (0)
#define PRINTF(f_, ...)                                                        \
	do {                                                                     \
	} while (0)
#endif

#endif
