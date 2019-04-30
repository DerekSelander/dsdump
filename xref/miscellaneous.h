//
//  miscellaneous.h
//  xref
//
//  Created by Derek Selander on 3/7/19.
//  Copyright © 2019 Selander. All rights reserved.
//


#ifndef MISCELLANEOUS_H
#define MISCELLANEOUS_H

@import Foundation;
#import "capstone/capstone.h"

NS_ASSUME_NONNULL_BEGIN


/// Usage deets
void print_usage(void);


/********************************************************************************
 /// Globals for exploring multiple references
 ********************************************************************************/

extern NSMutableSet <NSString*> *pathsSet;
extern NSMutableSet <NSString*> *exploredSet;
extern NSMutableSet <NSString*> *rpathSet;


typedef NS_OPTIONS(NSUInteger, DSCOLOR) {
    DSCOLOR_CYAN,
    DSCOLOR_YELLOW,
    DSCOLOR_MAGENTA,
    DSCOLOR_RED,
    DSCOLOR_BLUE,
    DSCOLOR_GRAY,
    DSCOLOR_GREEN,
    DSCOLOR_BOLD
};
char* dcolor(DSCOLOR c);

/// Ends the color option if the DSCOLOR env var is set
char *colorEnd(void);


#define VERBOSE_NONE 0
#define VERBOSE_1    1
#define VERBOSE_2    2
#define VERBOSE_3    3
#define VERBOSE_4    4

typedef struct {
    int showLibReferences;
    int verbose;
    int undefined;
    int objectiveC_mode;
    int all_symbols;
    int defined;
    int color;
    int use_regex;
    int external;
    int analyze;
    int all_sections;
    uintptr_t address;
    uintptr_t file_offset;
    char * symbol;
    char * library;
    char * showSymbolReferences;
    int debug;
} xref_options_t;

extern xref_options_t xref_options;


typedef struct {
    cs_insn ins;
    cs_detail detail;
} ds_ins;


//uint64_t read_uleb128 (const uint8_t ** offset, const uint8_t * end);
const uint8_t *r_uleb128_decode(uint8_t *data, int *datalen, uint64_t *v);
const uintptr_t r_sleb128_decode(uint8_t *byte, uintptr_t* shift, uint64_t *v);


/// sizeof pointer
#define PTR_SIZE sizeof(void*)

/// Only print if DEBUG flag is set
#define DEBUG_PRINT(fmt, args...)    if (xref_options.debug) printf(fmt, ## args)

NS_ASSUME_NONNULL_END

#endif // MISCELLANEOUS_H



