//
//  main.m
//  xref
//
//  Created by Derek Selander on 3/7/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <unistd.h>
#import <getopt.h>

#import "miscellaneous.h"
#import "DSXRLibrary.h"
#import "capstone/capstone.h"
#import "capstone/platform.h"
#import "DSXRLibrary+SymbolDumper.h"

@import MachO;
static NSArray <NSString *>* exc_rpaths = nil;

static DSXRLibrary *mainExecutable;

static void handle_args(int argc, const char * argv[]);

int main(int argc, const char * argv[], const char*envp[]) {
    
    handle_args(argc, argv);
    if (argc < 2) {
        print_usage();
        exit(1);
    }
    
    const char *_path = argv[optind++];
    NSString *path = [NSString stringWithUTF8String:_path];
    [pathsSet addObject:path];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        printf("File doesn't exist at \"%s\"\n", _path);
        exit(1);
    }
    
    mainExecutable = [[DSXRLibrary alloc] initWithPath:path];
    
    
    if (! (xref_options.address || xref_options.symbol || xref_options.file_offset  || xref_options.analyze)) {
        [mainExecutable dumpSymbols];
        return 0;
    }

    // Go through the options
    if (xref_options.address) {
        [mainExecutable dumpReferencesForAddress:xref_options.address];
    }
    if (xref_options.symbol) {
        [mainExecutable dumpReferencesForSymbol:[NSString stringWithUTF8String:xref_options.symbol]];
    }
    if (xref_options.file_offset) {
        [mainExecutable dumpReferencesForFileOffset:xref_options.file_offset];
    }
    
    return 0;
}


static void handle_args(int argc, const char * argv[]) {
    int c;
    int digit_optind = 0;
    
    while (1) {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
            {"library", required_argument, 0,  0 },
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
            {"all",    no_argument, &xref_options.all_symbols,  1 },
            {"debug",    no_argument, &xref_options.debug,  1 },
            {0,         0,                 0,  0 }
        };
        
        xref_options.debug = getenv("DSDEBUG") ? 1 : 0;
        c = getopt_long(argc, (char * const *)argv, "AuUxcvSs:o:l:a:bd:012",
                        long_options, &option_index);
        if (c == -1) { break; }
        switch (c) {
            case 0:
//                const char * opt_name = long_options[option_index].name;
                if (strcmp(long_options[option_index].name, "symbol") == 0) {
                    xref_options.symbol = optarg;
                } else if (strcmp(long_options[option_index].name, "library") == 0) {
                     xref_options.library = optarg;
                }  else if (strcmp(long_options[option_index].name, "address") == 0) {
                    xref_options.address = strtol(optarg, 0, 0);
                } else if (strcmp(long_options[option_index].name, "file_offset") == 0) {
                    xref_options.file_offset = strtol(optarg, 0, 0);
                } else if (strcmp(long_options[option_index].name, "verbose") == 0) {
                    xref_options.verbose = (int)strtol(optarg, 0, 0);
                }  else if (strcmp(long_options[option_index].name, "arch") == 0) {
                    xref_options.arch = optarg;
                }
//                if (optarg)
//                    printf(" with arg %s", optarg);
//                printf("\n");
                break;
                
            case '0':
            case '1':
            case '2':
                if (digit_optind != 0 && digit_optind != this_option_optind)
                    printf("digits occur in two different argv-elements.\n");
                digit_optind = this_option_optind;
                printf("option %c\n", c);
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
                xref_options.library = optarg;
                break;
            case 's':
                xref_options.symbol = optarg;
                break;
            case 'A':
//                xref_options.analyze = 1;
//                Disabled for now, till I can find something I am happy with
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
    

    
}
