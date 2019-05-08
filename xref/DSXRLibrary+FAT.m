//
//  DSXRLibrary+FAT.m
//  xref
//
//  Created by Derek Selander on 5/1/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "DSXRLibrary+FAT.h"
#include <sys/types.h>
#include <sys/sysctl.h>


@implementation DSXRLibrary (FAT)


//+ (void)load {
//    
//    int type = 0, subtype = 0;
//    size_t len;
//
//    sysctlbyname("hw.cputype", &type, &len, NULL, 0);
//    sysctlbyname("hw.cpusubtype", &subtype, &len, NULL, 0);
//    
//
////    printf("test\n");
//    
//    
//}

-(uintptr_t)getOffsetForSelectedArch {
    
    
    return 0;
}

@end
