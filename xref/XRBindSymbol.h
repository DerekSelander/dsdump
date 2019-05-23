//
//  DSXRObjCClass.h
//  xref
//
//  Created by Derek Selander on 4/22/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "uthash.h"

NS_ASSUME_NONNULL_BEGIN

@interface XRBindSymbol : NSObject

@property (nonatomic, assign) NSNumber *address;
@property (nonatomic, assign) int symidx;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, readonly) NSString *shortName;
@property (nonatomic, assign) uint64_t addend;
@property (nonatomic, assign) uint64_t libOrdinal;

- (instancetype)initWithAddress:(NSNumber *)address symbol:(NSString *)symbol libord:(uint64_t)ordinal addend:(uint64_t)addend;

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
