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
#import <dlfcn.h>

#import "miscellaneous.h"
#import "XRMachOLibrary.h"
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
        print_manpage();
        exit(1);
    }
    char resolved_path[PATH_MAX];
    if (!realpath(_path, resolved_path)) {
        printf("Couldn't resolved \"%s\"\n", _path);
        exit(1);
    }
    NSString *path = [NSString stringWithUTF8String:resolved_path];
    [pathsSet addObject:path];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        printf("File doesn't exist at \"%s\"\n", resolved_path);
        exit(1);
    }
    
    XRMachOLibrary *image = [[XRMachOLibrary alloc] initWithPath:path];
    // Go through the options
    if (! ( xref_options.file_offset  || xref_options.analyze || xref_options.library || xref_options.dump)) {
        [image dumpSymbols];
        return 0;
    }
    
    if (xref_options.library) {
        if (geteuid() != 0) {
            dprintf(STDERR_FILENO, "Needs root privledges for this operation\n");
            exit(1);
        }
        DumpProcessesContainingLibrary(basename(resolved_path));
    }

    
    return 0;
}


static void handle_args(int argc, const char * argv[]) {
    int c;
    
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"library", no_argument, &xref_options.library,  1 },
            {"arch",  required_argument, 0,  0 },
            {"regex",   no_argument,       &xref_options.use_regex,  1},
            {"verbose", optional_argument,     &xref_options.verbose,  1 },
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
        

        c = getopt_long(argc, (char * const *)argv, "a:hA:uUxcvSl",
                        long_options, &option_index);
        if (c == -1) { break; }
        struct host_basic_info;
        switch (c) {
            case 0:
                if (strcmp(long_options[option_index].name, "file_offset") == 0) {
                    xref_options.file_offset = strtol(optarg, 0, 0);
                } else if (strcmp(long_options[option_index].name, "verbose") == 0) {
                    xref_options.verbose = (int)strtol(optarg, 0, 0);
                }  else if (strcmp(long_options[option_index].name, "arch") == 0) {
                    xref_options.arch = optarg;
                } else if (strcmp(long_options[option_index].name, "help") == 0) {
                    print_manpage();
                    exit(0);
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
            case 'A':
                xref_options.arch = optarg;
                break;
            case 'h':
                print_manpage();
                exit(0);
                break;
                
            case 'a': {
                char *end;
                long address = strtoul(optarg, &end, 16);
                if (!address) {
                    address = strtoul(optarg, &end, 10);
                }
                if (!address) {
                    printf("-a needs a virtual address");
                    exit(1);
                }
                xref_options.virtual_address = address;
                xref_options.virtual_address_count = 1;
                if (strchr(optarg, ',')) {
                    char *post_comma = strchr(optarg, ',');
                    xref_options.virtual_address_count = (int)strtol(&post_comma[1], NULL, 10);
                    if (!xref_options.virtual_address_count) {
                        printf("Should be something like -a 0xffff,5\n");
                        exit(1);
                    }
                    
                }
                
            } case '?':
                break;
                
            default:
                printf("?? getopt returned character code 0%o ??\n", c);
        }
    }
    
    // Handle some post argument shuffling...
    if (xref_options.swift_mode) { xref_options.objectiveC_mode = 1; }
    xref_options.color |= getenv("DSCOLOR") ? 1 : 0;
    xref_options.debug |= getenv("DEBUG") ? 1 : 0;
    
    if (!xref_options.arch && getenv("ARCH")) {
        xref_options.arch = getenv("ARCH");
    }
    
}
