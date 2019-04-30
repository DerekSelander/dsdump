//
//  DSXRObjCClass.h
//  xref
//
//  Created by Derek Selander on 4/22/19.
//  Copyright © 2019 Selander. All rights reserved.
//

@import Foundation;
//#import <Foundation/Foundation.h>
#import "uthash.h"
//#include <stdlib.h>

NS_ASSUME_NONNULL_BEGIN

@interface DSXRObjCClass : NSObject

@property (nonatomic, assign) NSNumber *address;
@property (nonatomic, assign) int symidx;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, readonly) NSString *shortName;

- (instancetype)initWithAddress:(NSNumber *)address symbol:(NSString *)symbol;

@end


typedef struct {
    uintptr_t address;
    char *name;
//    UT_hash_handle hh;
} dsclass_ref;
typedef dsclass_ref * dsclass_ref_t;

dsclass_ref_t ClassRefCreate(uintptr_t address, char *symbol);
const char * ClassRefGetName(dsclass_ref_t ref);


void hash_add_objcref_addr(dsclass_ref_t ref);
dsclass_ref_t hash_get_objcref_addr(uintptr_t address);

void hash_add_objcref_str(dsclass_ref_t ref);
dsclass_ref_t hash_get_objcref_str(char* str);


NS_ASSUME_NONNULL_END
