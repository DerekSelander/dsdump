//
//  miscellaneous.h
//  xref
//
//  Created by Derek Selander on 3/7/19.
//  Copyright © 2019 Selander. All rights reserved.
//


#ifndef MISCELLANEOUS_H
#define MISCELLANEOUS_H

#import <Foundation/Foundation.h>
#import <stdlib.h>
#import <Foundation/Foundation.h>

#ifdef __cplusplus

extern "C" {
#endif

/// Usage deets
void print_manpage(void);
void print_usage(void);

__attribute__((weak)) unsigned char __manpage_deets;
/********************************************************************************
 /// Globals for exploring multiple references
 ********************************************************************************/

typedef NS_OPTIONS(NSUInteger, DSCOLOR) {
    DSCOLOR_CYAN,
    DSCOLOR_YELLOW,
    DSCOLOR_MAGENTA,
    DSCOLOR_RED,
    DSCOLOR_PURPLE,
    DSCOLOR_BLUE,
    DSCOLOR_GRAY,
    DSCOLOR_GREEN,
    DSCOLOR_BOLD,
    DSCOLOR_CYAN_UNDERLINE,
    DSCOLOR_PURPLE_BOLD,
    DSCOLOR_CYAN_LIGHT,
    DSCOLOR_YELLOW_LIGHT
};
char const* dcolor(DSCOLOR c);

/// Ends the color option if the DSCOLOR env var is set
char const* color_end(void);

/// Different levels to logging, opted for a "codesign -vvvv" style
#define VERBOSE_NONE 0
#define VERBOSE_1    1
#define VERBOSE_2    2
#define VERBOSE_3    3
#define VERBOSE_4    4

typedef struct {
    int verbose;
    int undefined;
    int objectiveC_mode;
    int swift_mode;
    int symbol_mode;
    int all_symbols;
    int defined;
    int color;
    int use_regex;
    int external;
    int analyze;
    uintptr_t file_offset;
    uintptr_t virtual_address;
    int virtual_address_count; 
    int library;
    char * arch;
    int debug;
    int help;
    int opcodes;
} xref_options_t;

extern xref_options_t xref_options;


/// Read unsigned leb128 coding
const uint8_t *r_uleb128_decode(uint8_t *data, int *datalen, uint64_t *v);

/// Read signed leb128 coding
const uintptr_t r_sleb128_decode(uint8_t *byte, uintptr_t* shift, uint64_t *v);

/// Used to check for class filtering
BOOL ContainsFilteredWords(const char *word);

/// Used to input filters for checking for filtering
void AddFilter(char * filter);

/// Only print when DEBUG env var is set
void warn_debug(const char *format, ...);

#ifdef __cplusplus
}
#endif

/// sizeof pointer, 64 bit only
#define PTR_SIZE sizeof(void*)

/// Only print if DEBUG flag is set
#define DEBUG_PRINT(fmt, args...)    if (xref_options.opcodes) { printf(fmt, ## args); }

#endif // MISCELLANEOUS_H
