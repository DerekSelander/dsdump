//
//  XRSymbolEntry.m
//  xref
//
//  Created by Derek Selander on 5/22/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRSymbolEntry.h"
#import "XRMachOLibrary.h"

@implementation XRSymbolEntry

-(instancetype)initWithSymbol:(struct nlist_64 *)symbol machoLibrary:(XRMachOLibrary*)lib {
    if (self = [super init]) {
        _name = (const char*)&lib.str_symbols[symbol->n_un.n_strx];
        _address = symbol->n_value;
    }
    return self;
}

- (NSString *)debugDescription {
    return [NSString stringWithFormat:@"%p, name: %s addr:%p", self, _name, (void*)_address];
}

@end
