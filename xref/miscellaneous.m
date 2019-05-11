//
//  miscellaneous.m
//  xref
//
//  Created by Derek Selander on 3/7/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "miscellaneous.h"

BOOL quiet_mode = NO;
NSMutableSet <NSString*> *pathsSet = nil;
NSMutableSet <NSString*> *exploredSet = nil;
NSMutableSet <NSString*> *rpathSet = nil;

xref_options_t xref_options;

__attribute__((constructor)) static void InitializeStuff() {
    pathsSet = [NSMutableSet set];
    exploredSet = [NSMutableSet set];
    rpathSet = [NSMutableSet set];
}

/********************************************************************************
 //  Options 
 ********************************************************************************/

static const char *_options[] = {
    "--objc           Dumps Objective-C classes\n",
    "--swift          Dumps Swift classes\n",
    "--all            Search in all functions, even ones that are stripped out\n",
    "--arch      (-A) <arch> Display info for specified arch (defaults to your CPU)\n",
    "--verbose   (-v) <level>  verbose modes, there are 4 levels\n",
    "--symbol    (-s) <symbol> Find references to a symbol, use --objc for non-C\n",
    "--undefined (-u) Dump only undefined (externally referenced) symbols\n",
    "--defined   (-U) Dump only defined (internally implemented) symbols\n",
    "--library   (-l) Dump only defined (internally implemented) symbols\n"
};

void print_usage() {
    static char* desc =
    " Usage: %s <options> macho_file\n";
    printf("%s\n", desc);
}

void print_options() {
    static char* desc =
    " Usage: xref <options> macho_file\n A cross between nm and vmmap for finding references to symbols (C, ObjC, Swift), both statically and in programs in memory\n";
    printf("%s\n", desc);
    for (int i = 0; i < sizeof(_options)/sizeof(_options[0]); i++) {
        printf("  %s\n", _options[i]);
    }
}

/********************************************************************************
 //  Colors!
 ********************************************************************************/

char* dcolor(DSCOLOR c) {
    static BOOL useColor = NO;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        if (xref_options.color || getenv("DSCOLOR")) {
            useColor = YES;
        }
    });
    if (!useColor) {
        return "";
    }
    
    switch (c) {
        case DSCOLOR_CYAN:
            return "\e[36m";
        case DSCOLOR_GREEN:
            return "\e[92m";
        case DSCOLOR_YELLOW:
             return "\e[33m";
        case DSCOLOR_MAGENTA:
            return "\e[95m";
        case DSCOLOR_RED:
            return "\e[91m";
        case DSCOLOR_BLUE:
            return "\e[34m";
        case DSCOLOR_GRAY:
            return "\e[90m";
        case DSCOLOR_BOLD:
             return "\e[1m";
        default:
            return "";
    }
}

char *color_end() {
    static BOOL useColor = NO;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        if (xref_options.color || getenv("DSCOLOR")) {
            useColor = YES;
        }
    });
    if (useColor) {
        return "\e[0m";
    }
    return "";
}

/********************************************************************************
 //  Leb128 Encoding
 ********************************************************************************/

/* Read a ULEB128 into a 64-bit word.  Return (uint64_t)-1 on overflow
 or error.  On overflow, skip past the rest of the uleb128.  */
uint64_t read_uleb128 (const uint8_t ** offset, const uint8_t * end) {
    uint64_t result = 0;
    int bit = 0;
    
    do  {
        uint64_t b;
        
        if (*offset == end)
            return (uint64_t) -1;
        
        b = **offset & 0x7f;
        
        if (bit >= 64 || b << bit >> bit != b) {
            result = (uint64_t) -1;
        } else {
            result |= b << bit;
            bit += 7;
        }
    } while (*(*offset)++ >= 0x80);
    return result;
}

/// Unsigned Leb128
const uint8_t *r_uleb128_decode(uint8_t *data, int *datalen, uint64_t *v) {
    uint8_t c = 0xff;
    uint64_t s = 0, sum = 0, l = 0;
    if (data && *data) {
        do {
            c = *(data++) & 0xff;
            sum |= ((uint64_t) (c & 0x7f) << s);
            s += 7;
            l++;
        } while (c & 0x80);
    }
    if (v)  {*v = sum; }
    if (datalen) { *datalen = (int)l; }
    return data;
}

/// Signed Leb128
const uintptr_t r_sleb128_decode(uint8_t *byte, uintptr_t* datalen, uint64_t *v) {
    uintptr_t result = 0;
    uintptr_t shift = 0;
    
    size_t size = sizeof(signed int);
    uint8_t *cur = byte;
    int l =0 ;
    do{
        l++;
        result |= ((0x7f & *cur) << shift);
        shift += 7;
    } while((*cur & 0x80) != 0);
    
    /* sign bit of byte is second high order bit (0x40) */
    if ((shift < size) && (*cur & 0x80)) {
        /* sign extend */
        result |= (~0 << shift);
    }
    
    if (v) { *v = result; }
    if (datalen) { *datalen = l; }
    return result;
}
