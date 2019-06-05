//
//  XRMachOLibrary+FileManagement.m
//  xref
//
//  Created by Derek Selander on 4/10/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary.h"
#import <sys/mman.h>

//#define PAYLOAD_FILE_SIZE(c)  (sizeof(long) + (sizeof(cs_insn) * (c)) + (sizeof(cs_detail) * (c)))


@implementation XRMachOLibrary (FileManagement)


////////////////////////////////////////////////////////////////
// Public methods
////////////////////////////////////////////////////////////////


- (NSString *)translateUUID {
    char uuid_output[37];
    for (int cur = 0, i = 0; i < 16; i++) {
        char c = self.uuid_cmd->uuid[i];
        char lower = c & 0xf;
        char upper = (c & 0xf0) >> 4;
        
        if (upper < 10) {
            upper += 48;
        } else {
            upper += 55;
        }
        
        if (lower < 10) {
            lower += 48;
        } else {
            lower += 55;
        }
        uuid_output[cur++] = upper;
        uuid_output[cur++] = lower;
        if (i == 3 || i == 5 || i == 7 || i == 9) {
            uuid_output[cur++] = '-';
        }
        uuid_output[cur] = '\x00';
    }
    
    return [NSString stringWithUTF8String:uuid_output];
}

- (NSString *)analysisSavePath {
    return [NSString stringWithFormat:@"/tmp/com.selander.xref.%@", [self translateUUID]];
}


@end




