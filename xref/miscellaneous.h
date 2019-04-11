//
//  miscellaneous.h
//  xref
//
//  Created by Derek Selander on 3/7/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "DSXRExecutable.h"

/// Usage deets
void print_usage(void);

extern NSMutableSet <NSString*> *pathsSet;
extern NSMutableSet <NSString*> *exploredSet;
extern NSMutableSet <NSString*> *rpathSet;

extern DSXRExecutable *mainExecutable;



/**
 Uses color of the DSCOLOR env var is set or -r option is used
 Possible options are:
 
 cyan
 yellow
 magenta
 red
 blue
 gray
 bold
 
 
 
 You must use the *colorEnd* function to stop using that color
 */

typedef NS_OPTIONS(NSUInteger, DSCOLOR) {
    DSCOLOR_CYAN,
    DSCOLOR_YELLOW,
    DSCOLOR_MAGENTA,
    DSCOLOR_RED,
    DSCOLOR_BLUE,
    DSCOLOR_GRAY,
    DSCOLOR_BOLD
};
char* dcolor(DSCOLOR c);

/// Ends the color option if the DSCOLOR env var is set
char *colorEnd(void);

/// My printf
void dsprintf(FILE * f, const char *format, ...);

/// Enabled by DSDEBUG env var
void dsdebug(const char *format, ...);

/// Message then die
void ErrorMessageThenDie(const char *message, ...);

/// If true this will disable stderr/stdout
//extern BOOL quiet_mode;

///// Self explanatory, right?... right?
//void print_manpage(void);


///

typedef struct {
    int showLibReferences;
    int verbose;
    int undefined;
    int defined;
    int color;
    int use_regex;
    int external;
    int save_data;
    int all_sections;
    uintptr_t address;
    uintptr_t file_offset;
    char * symbol;
    char * library;
    char * showSymbolReferences;
    
} xref_options_t;

extern xref_options_t xref_options;


//uint64_t read_uleb128 (const uint8_t ** offset, const uint8_t * end);
const uint8_t *r_uleb128_decode(uint8_t *data, int *datalen, uint64_t *v);
