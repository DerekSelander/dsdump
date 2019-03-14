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
@import MachO;

static NSArray <NSString *>* exc_rpaths = nil;



static void handleARGS(int argc, const char * argv[]);

int main(int argc, const char * argv[], const char*envp[]) {
    
    
    handleARGS(argc, argv);
    if (argc < 2) {
        printUsage();
        exit(1);
    }
    const char * p = argv[optind++];
    NSString *path = [NSString stringWithUTF8String:p];
    [pathsSet addObject:path];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        printf("File doesn't exist at \"%s\"\n", argv[1]);
        exit(1);
    }
    _dyld_image_count();
    mainExecutable = [[DSXRExecutable alloc] initWithPath:path];
    
    if (xref_options.external) {
        [mainExecutable dumpExternalSymbols];
    } else if (xref_options.address) {
        [mainExecutable findAddressInCode_x86:xref_options.address];
    }  else if (xref_options.symbol) {
        [mainExecutable findAddressesForSymbolInCode:[NSString stringWithUTF8String:xref_options.symbol]];
    }   else if (xref_options.file_offset) {
            [mainExecutable findOffsetsInCode:xref_options.file_offset];
        }
     else {
        [mainExecutable dumpSymbols];
    }
    
    
//    NSMutableDictionary *libs = [NSMutableDictionary dictionary];
//    [libs setObject:mainExecutable forKey:mainExecutable.path];
//
//
//    while ([pathsSet count]) {
//        NSSet <NSString*> *s = [pathsSet objectsPassingTest:^BOOL(NSString * _Nonnull obj, BOOL * _Nonnull stop) {
//            if (![exploredSet containsObject:obj]) {
//                *stop = YES;
//                return YES;
//            }
//            return NO;
//        }];
//
//        NSString *anyPath = [s anyObject];
//        if (!anyPath) { break; }
//        DSXRLibrary *lib = [[DSXRLibrary alloc] initWithPath:anyPath];
//        [pathsSet removeObject:anyPath];
//        [libs setObject:lib forKey:lib.path];
//    }
    
    return 0;
}


static void handleARGS(int argc, const char * argv[]) {
    int c;
    int digit_optind = 0;
    
    while (1) {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
            {"library", required_argument, 0,  0 },
            {"symbol",  required_argument, 0,  0 },
            {"file_offset",  required_argument, 0,  0 },
            {"regex",   no_argument,       &xref_options.use_regex,  1},
            {"verbose", no_argument,       &xref_options.verbose,  1 },
            {"external", no_argument,      &xref_options.external,  1 },
            {"address",  required_argument, 0, 'c'},
            {"color",    no_argument, &xref_options.color,  1 },
            {0,         0,                 0,  0 }
        };
        
        c = getopt_long(argc, (char * const *)argv, "xcvs:o:l:a:bd:012",
                        long_options, &option_index);
        if (c == -1)
            break;
        
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
                xref_options.verbose = 1;
                break;
            case 'c':
                xref_options.color = 1;
                break;
            case 'l':
                xref_options.library = optarg;
                break;
            case 's':
                xref_options.symbol = optarg;
                break;
            case 'a':
                xref_options.address = strtol(optarg, 0, 0);
                break;
            case 'o':
                
                xref_options.file_offset = strtol(optarg, 0, 0);
                break;
                
            case 'x':
                xref_options.external = 1;
//                printf("option b\n");
                break;
                
         
                
            case 'd':
//                printf("option d with value '%s'\n", optarg);
                break;
                
            case '?':
                break;
                
            default:
                printf("?? getopt returned character code 0%o ??\n", c);
        }
    }
    
//    if (optind < argc) {
//        printf("non-option ARGV-elements: ");
//        while (optind < argc)
//            printf("%s ", argv[optind++]);
//        printf("\n");
//    }
    
    
    
}
