//
//  XRMachOLibrary+Swift.m
//  xref
//
//  Created by Derek Selander on 5/18/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary+Swift.h"
#import <dlfcn.h>

@implementation XRMachOLibrary (Swift)

static void(*ds_xcselect_get_developer_dir_path)(const char *ptr, size_t length, uintptr_t *a, uintptr_t *b, uintptr_t *c);

- (BOOL)loadSwiftDemangle {
    
    // First we need to figure out where the hey Xcode is, so consult libxcselect.dylib...
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        void* handle = dlopen("/usr/lib/libxcselect.dylib", RTLD_NOW);
        ds_xcselect_get_developer_dir_path = dlsym(handle, "xcselect_get_developer_dir_path");
    });

    if (!ds_xcselect_get_developer_dir_path)  { return NO; }


    // Hokay found the function xcselect_get_developer_dir_path, consult that for path...
    char xcode_path[PATH_MAX];
    uintptr_t dunno1, dunno2, dunno3;
    const char * libxcrun_path = "/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-demangle";
    ds_xcselect_get_developer_dir_path(xcode_path, PATH_MAX, &dunno1, &dunno2, &dunno3);
    
    
    // Append path component to location of swift-demangle
    strncpy(&xcode_path[strlen(xcode_path)], libxcrun_path, strlen(libxcrun_path) + 1);

    

    
    return YES;
}

//- (const char *)demangledSwiftName:(const char*)name {


/*
 // expects code to be linked to /usr/lib/xcselect.dylib ("xcode-select -p" equivalent)
 static char *xcode_path() {
 char *input = calloc(0x400, sizeof(char));
 char dunno1, dunno2, dunno3;
 void* xcselect_get_developer_dir_path(char *ptr, size_t length, char *a, char*b, char *c);
 xcselect_get_developer_dir_path(input, 0x400, &dunno1, &dunno2, &dunno3);
 return input;
 }
 */
@end
