//
//  main.m
//  xref
//
//  Created by Derek Selander on 3/7/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <unistd.h>
#include <libgen.h>
#import <getopt.h>

#import "miscellaneous.h"
#import "XRMachOLibrary.h"
#import "capstone/capstone.h"
#import "capstone/platform.h"
#import "XRMachOLibrary+SymbolDumper.h"
#import "TaskPath.h"

@import MachO;

/*******************************************************************************
 
 *******************************************************************************/
static NSArray <NSString *>* exc_rpaths = nil;
static void handle_args(int argc, const char * argv[]);



int main(int argc, const char * argv[], const char*envp[]) {
    handle_args(argc, argv);
    if (argc < 2) {
        print_usage();
        exit(1);
    }
    
    const char *_path = argv[optind++];
    if (!_path) {
        print_usage();
        exit(1);
    }
    char resolved_path[PATH_MAX];
    NSString *path = [NSString stringWithUTF8String:realpath(_path, resolved_path)];
    [pathsSet addObject:path];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        printf("File doesn't exist at \"%s\"\n", resolved_path);
        exit(1);
    }
    
    XRMachOLibrary *image = [[XRMachOLibrary alloc] initWithPath:path];
    if (! (xref_options.address || xref_options.symbol || xref_options.file_offset  || xref_options.analyze || xref_options.library || xref_options.dump)) {
        [image dumpSymbols];
        return 0;
    }
    
    // Go through the options
    if (xref_options.address) {
        [image dumpReferencesForAddress:xref_options.address];
    }
    if (xref_options.library) {
        if (geteuid() != 0) {
            dprintf(STDERR_FILENO, "Needs root privledges for this operation\n");
            exit(1);
        }
        DumpProcessesContainingLibrary(basename(resolved_path));
    }
    if (xref_options.symbol) {
        [image dumpReferencesForSymbol:[NSString stringWithUTF8String:xref_options.symbol]];
    }
    if (xref_options.file_offset) {
        [image dumpReferencesForFileOffset:xref_options.file_offset];
    }
    
    return 0;
}


static void handle_args(int argc, const char * argv[]) {
    int c;
//    int digit_optind = 0;
    
    while (1) {
//        int this_option_optind = optind ? optind : 1;method_array_t
        int option_index = 0;
        static struct option long_options[] = {
            {"library", no_argument, &xref_options.library,  1 },
            {"symbol",  required_argument, 0,  0 },
            {"arch",  required_argument, 0,  0 },
            {"file_offset",  required_argument, 0,  0 },
            {"regex",   no_argument,       &xref_options.use_regex,  1},
            {"verbose", optional_argument,     &xref_options.verbose,  1 },
            {"analyze", no_argument,       &xref_options.analyze,  1 },
            {"address",  required_argument, 0, 'c'},
            {"color",    no_argument, &xref_options.color,  1 },
            {"defined",    no_argument, &xref_options.defined,  1 },
            {"undefined",    no_argument, &xref_options.undefined,  1 },
            {"objc",    no_argument, &xref_options.objectiveC_mode,  1 },
            {"swift",    no_argument, &xref_options.swift_mode,  1 },
            {"all",    no_argument, &xref_options.all_symbols,  1 },
            {"debug",    no_argument, &xref_options.debug,  1 },
            {"help",    no_argument, &xref_options.help,  1 },
            {0,         0,                 0,  0 }
        };
        
        xref_options.debug = getenv("DEBUG") ? 1 : 0;
        c = getopt_long(argc, (char * const *)argv, "A:uUxcvSs:o:la:bd:012",
                        long_options, &option_index);
        if (c == -1) { break; }
        struct host_basic_info;
        switch (c) {
            case 0:
                if (strcmp(long_options[option_index].name, "symbol") == 0) {
                    xref_options.symbol = optarg;
                } else if (strcmp(long_options[option_index].name, "address") == 0) {
                    xref_options.address = strtol(optarg, 0, 0);
                } else if (strcmp(long_options[option_index].name, "file_offset") == 0) {
                    xref_options.file_offset = strtol(optarg, 0, 0);
                } else if (strcmp(long_options[option_index].name, "verbose") == 0) {
                    xref_options.verbose = (int)strtol(optarg, 0, 0);
                }  else if (strcmp(long_options[option_index].name, "arch") == 0) {
                    xref_options.arch = optarg;
                }
                break;
            case 'v':
                xref_options.verbose++;
                break;
            case 'c':
                xref_options.color = 1;
                break;
            case 'u':
                xref_options.undefined = 1;
                break;
            case 'U':
                xref_options.defined = 1;
                break;
            case 'l':
                xref_options.library = 1;
                break;
            case 's':
                xref_options.symbol = optarg;
                break;
            case 'A':
                xref_options.arch = optarg;
                break;
            case 'a':
                xref_options.address = strtol(optarg, 0, 0);
                break;
            case 'o':
                xref_options.file_offset = strtol(optarg, 0, 0);
                break;
            case 'S':
                xref_options.all_sections = 1;
                break; 
//            case 'x':
//                xref_options.external = 1;
////                printf("option b\n");
//                break;
                
         
                
//            case 'd':
////                printf("option d with value '%s'\n", optarg);
//                break;
                
            case '?':
                break;
                
            default:
                printf("?? getopt returned character code 0%o ??\n", c);
        }
    }
    
    // Handle some post argument shuffling...
    if (xref_options.swift_mode) { xref_options.objectiveC_mode = 1; }
    xref_options.debug |= getenv("DSDEBUG") ? 1 : 0;
    xref_options.color |= getenv("DSCOLOR") ? 1 : 0;
    
    if (!xref_options.arch && getenv("ARCH")) {
        xref_options.arch = getenv("ARCH");
    }
    
}
