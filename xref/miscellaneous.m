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
NSMutableSet <NSString*> *rpathSet;

xref_options_t xref_options;

static void __attribute__((constructor))InitializeStuff() {
    pathsSet = [NSMutableSet set];
    exploredSet = [NSMutableSet set];
    rpathSet = [NSMutableSet set];
}


void print_usage() {
    static char* desc =
    "Usage: xref <options> file\n\
    \t-s symbol\tsearches for references for that symbol in code\n\
    \t-x \t\texternal symbols, lists undefined symbols\n\
    \t-v \t\tverbose\n\
    \t-c \t\tUse color, alternatively export DSCOLOR environment var\n";
    printf("%s\n", desc);
}




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

char *colorEnd() {
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
//
//void dsprintf(FILE * f, const char *format, ...) {
//    if (quiet_mode) {
//        return;
//    }
//    va_list args;
//    va_start( args, format );
//    vfprintf(f, format, args );
//    va_end( args );
//}
//
//void dsdebug(const char *format, ...) {
//    if (quiet_mode) { return; }
//    
//    static dispatch_once_t onceToken;
//    static BOOL debugFlag = 0;
//    dispatch_once(&onceToken, ^{
//        if (getenv("DSDEBUG")) {
//            debugFlag = YES;
//        } else {
//            debugFlag = NO;
//        }
//    });
//    
//    if (debugFlag) {
//        va_list args;
//        va_start( args, format);
//        vfprintf(stdout, format, args );
//        va_end( args );
//    }
//    
//}


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

/*
 
 const uint8_t* infoStart = (uint8_t*)fHeader + fFunctionStartsInfo->dataoff();
 const uint8_t* infoEnd = &infoStart[fFunctionStartsInfo->datasize()];
 uint64_t address = fBaseAddress;
 for(const uint8_t* p = infoStart; (*p != 0) && (p < infoEnd); ) {
 uint64_t delta = 0;
 uint32_t shift = 0;
 bool more = true;
 do {
 uint8_t byte = *p++;
 delta |= ((byte & 0x7F) << shift);
 shift += 7;
 if ( byte < 0x80 ) {
 address += delta;
 printFunctionStartLine(address);
 more = false;
 }
 } while (more);
 }
 }
 */

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


const uintptr_t r_sleb128_decode(uint8_t *byte, uintptr_t* datalen, uint64_t *v) {
    uintptr_t result = 0;
    uintptr_t shift = 0;
    
    size_t size = sizeof(signed int);
    uint8_t *cur = byte;
    int l;
    do{
        
        l++;
        result |= ((0x7f & *cur) << shift);
        shift += 7;
    }while((*cur & 0x80) != 0);
    
    /* sign bit of byte is second high order bit (0x40) */
    if ((shift < size) && (*cur & 0x80)) {
        /* sign extend */
        result |= (~0 << shift);
    }
    
    if (v) {*v = result;}
    if (datalen) {*datalen = l;}
    return result;
}
