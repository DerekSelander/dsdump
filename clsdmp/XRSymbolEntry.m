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

/*
for (int i = 0; i < self.symtab->nsyms; i++) {
    struct nlist_64 symbol = self.symbols[i];
    
    // If a debugging symbol only print if really verbose
    if ((symbol.n_type & N_STAB) && xref_options.verbose < VERBOSE_3) {
        continue;
    }
    
    if (xref_options.defined || xref_options.undefined) {
        if ((xref_options.defined && symbol.n_type & N_TYPE & N_SECT) || (xref_options.undefined && (symbol.n_type & N_TYPE) == N_UNDF)) {
            print_symbol(self, &self.symbols[i], NULL);
        }
    } else {
        print_symbol(self, &self.symbols[i], NULL);
    }
    
    // For stripped functions
    if (xref_options.all_symbols && symbol.n_value && self.symbolEntry[@(symbol.n_value)]) {
        XRSymbolEntry *entry = self.symbolEntry[@(symbol.n_value)];
        entry.visited = true;
    }
}
*/
