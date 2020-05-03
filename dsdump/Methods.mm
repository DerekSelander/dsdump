//
//  Methods.cpp
//  dsdump
//
//  Created by Derek Selander on 4/29/20.
//  Copyright © 2020 Selander. All rights reserved.
//

#include "Methods.h"
extern NSDictionary <NSString*, NSNumber*> *blacklistedSelectors;

void dumpObjectiveCMethods(method_list_t* methodList, const char *name, bool isMeta, bool isProtocol) {

    if (methodList == nullptr) {
        return;
    }

    auto count = methodList->disk()->count;
    auto methods = &methodList->disk()->first_method;
    if (xref_options.verbose > VERBOSE_2) {
        printf("\t// %s methods\n", isMeta ? "class" : "instance");
    }
    
    for (int i = 0; i < count; i++) {
        auto method = methods[i];
        auto methodAddress = method.imp->strip_PAC();
        auto types = method.types->disk();
        auto methodName = method.name->disk();
        if (blacklistedSelectors[[NSString stringWithUTF8String:methodName]]) {
            continue;
        }
        if (isProtocol) {
            printf("\t%s%c[%s %s]%s\n", dcolor(DSCOLOR_BOLD), "-+"[isMeta ? 1 : 0], name, methodName, color_end());
        } else {
            printf("\t%s0x%011lx%s %s%c[%s %s]%s\n", dcolor(DSCOLOR_GRAY), (unsigned long)methodAddress, color_end(), dcolor(DSCOLOR_BOLD), "-+"[isMeta ? 1 : 0], name, methodName, color_end());
        }
    }
    
    if (xref_options.verbose > VERBOSE_2) {
        putchar('\n');
    }

}
