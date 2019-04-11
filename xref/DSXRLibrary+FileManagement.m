//
//  DSXRLibrary+FileManagement.m
//  xref
//
//  Created by Derek Selander on 4/10/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "DSXRLibrary+FileManagement.h"
#import <sys/mman.h>

@implementation DSXRLibrary (FileManagement)


-(BOOL)loadFileIfAvailable {
    
    NSString *filePath = [self savePath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
        return NO;
    }
    
    
    
    return YES;
}

-(BOOL)saveFile {
//    self.uuid_cmd

    int fd = open([[self savePath] UTF8String], O_RDWR);
    if (!fd) { return NO; }
    
    off_t result = lseek(fd, 1024, SEEK_SET);
    if (result == -1) {
        close(fd);
        return NO;
    }
    
    result = write(fd, "", 1);
    if (result != 1) {
        close(fd);
        return NO;
    }
//    mmap(<#void *#>, <#size_t#>, PROT_READ|PROT_WRITE, MAP_SHARED, fd, <#off_t#>)
    
    return YES;
}

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

- (NSString *)savePath {
    NSString *applicationPath = [[[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask] lastObject] path];
    return [[applicationPath stringByAppendingPathComponent:@"com.selander.xref"] stringByAppendingPathComponent:[self translateUUID]];
}

@end
