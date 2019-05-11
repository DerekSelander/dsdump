//
//  XRMachOLibrary+Dump.m
//  xref
//
//  Created by Derek Selander on 5/11/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary+Dump.h"

@implementation XRMachOLibrary (Dump)

- (void)dumpFileOffset:(off_t)offset count:(uint8_t)count grouping:(uint8_t)grouping format:(char)format {
    
//    uintptr_t cur = offset;
//
//    for (int i = 0; i < count; i++) {
//        printf("%0x ", &self.data[cur + i * count]);
//        if (i % 2 == 0) { putchar('\n'); }
//    }

    if (format == 's') {
        
    }
    
    if (format == 't') {
        
    }
    
    if (format == 'd') {
        
    }
}

@end
