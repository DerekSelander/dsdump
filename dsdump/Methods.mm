//
//  Methods.cpp
//  dsdump
//
//  Created by Derek Selander on 4/29/20.
//  Copyright © 2020 Selander. All rights reserved.
//

#include "Methods.h"
char *
encoding_copyArgumentType(const char *t, unsigned int index);

char *
encoding_copyReturnType(const char *t);

void
encoding_getArgumentType(const char *t, unsigned int index,
                         char *dst, size_t dst_len);

void
encoding_getReturnType(const char *t, char *dst, size_t dst_len);

unsigned int
encoding_getArgumentInfo(const char *typedesc, unsigned int arg,
                         const char **type, int *offset);

unsigned
encoding_getSizeOfArguments(const char *typedesc);

unsigned int
encoding_getNumberOfArguments(const char *typedesc);

extern NSDictionary <NSString*, NSNumber*> *blacklistedSelectors;

void dumpObjectiveCMethods(method_list_t* methodList, const char *name, bool isMeta, bool isProtocol, const char * overrideColor) {

    if (methodList == nullptr) {
        return;
    }

    auto methodListDisk =  methodList->disk();
    auto count = methodListDisk->count;
    if (xref_options.verbose > VERBOSE_2) {
        printf("  %s// %s methods%s\n", dcolor(DSCOLOR_GRAY), isMeta ? "class" : "instance", color_end());
    }
    
    for (int i = 0; i < count; i++) {
        auto method = methodListDisk->GetMethod(i, isProtocol); //&methods[i];
        
        auto methodName = isProtocol ? method->name->disk() : method->getName()->disk();
        if (blacklistedSelectors[[NSString stringWithUTF8String:methodName]]) {
            continue;
        }
        
        uintptr_t methodAddress = isProtocol ? method->imp->strip_PAC() : (uintptr_t)method->getImp()->load();
        auto types = isProtocol ? method->types->disk() : method->getTypes()->disk();
        auto numArguments = encoding_getNumberOfArguments(types);
        
        char path[1024];
        encoding_getReturnType(types, path, 1024);
        
        putchar(' ');
        if (xref_options.verbose > VERBOSE_2 && !isProtocol) {
            printf(" %s0x%011lx%s ", overrideColor ? overrideColor: dcolor(DSCOLOR_GRAY), (unsigned long)methodAddress, color_end());
        }
        
        if (xref_options.verbose <= VERBOSE_4) {
            printf("%s%c[%s %s]%s\n", overrideColor? overrideColor : dcolor(DSCOLOR_BOLD), "-+"[isMeta ? 1 : 0], name, methodName, color_end());
            continue;
        }
        printf("%c(%s%s%s)", "-+"[isMeta ? 1 : 0], overrideColor? overrideColor : dcolor(DSCOLOR_BOLD),  translate_method_type_to_string(path), color_end());
        
//        if (isProtocol) {
//            printf("\t%s%c[%s %s\n", dcolor(DSCOLOR_BOLD), "-+"[isMeta ? 1 : 0], name, color_end());
//        } else {
//            printf("%s%c[%s %s]%s\n", dcolor(DSCOLOR_BOLD), "-+"[isMeta ? 1 : 0], name, methodName, color_end());
//        }
        long index = 0; // (int)(h - methodName);
        auto len = strlen(methodName);
        for (int i = 0; i < numArguments && index < len; i++) {
            auto found = strchr(&methodName[index], ':');
            if (!found) { // hit end of str or no args
                printf("%s%s%s", overrideColor ? overrideColor : dcolor(DSCOLOR_BOLD), &methodName[index], color_end());
                break;
            }
            found++;
            auto cur = (found - &methodName[index]);
            char dest[1024] = {};
            encoding_getArgumentType(types, i, dest, 1024);
            printf("%s%.*s(%s)%sarg%d", overrideColor ? overrideColor : dcolor(DSCOLOR_BOLD), (int)cur, &methodName[index],   translate_method_type_to_string(dest), color_end(), i+1);
            index = (found - methodName);
            if (i < numArguments - 1) {
                putchar(' ');
            }
        }
        putchar('\n');
    }
    
    if (xref_options.verbose > VERBOSE_2) {
        putchar('\n');
    }

}
