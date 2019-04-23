//
//  DSXRLibrary+SymbolDumper.m
//  xref
//
//  Created by Derek Selander on 4/22/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "DSXRLibrary+SymbolDumper.h"

@implementation DSXRLibrary (SymbolDumper)



/********************************************************************************
 // Dump symbols
 ********************************************************************************/

- (void)dumpSymbols {
    
    if (xref_options.objc_only) {
        [self dumpObjectiveCSymbols];
        return;
    }
    
    for (int i = 0; i < self.symtab->nsyms; i++) {
        
        struct nlist_64 symbol = self.symbols[i];
        
        // if stripped
        if (!symbol.n_un.n_strx)  { continue; }
        
        
        char * chr = &self.str_symbols[symbol.n_un.n_strx];
        // If not a valid symbol
        if (strlen(chr) < 2) { continue; }
        
        // If a debugging symbol only print if really verbose
        if ((symbol.n_type & N_TYPE & N_STAB) && xref_options.verbose < 2) { continue; }
        
        if (xref_options.defined || xref_options.undefined) {
            
            if ((xref_options.defined && symbol.n_type & N_TYPE & N_SECT) || (xref_options.undefined && (symbol.n_type & N_TYPE) == N_UNDF)) {
                [self printSymbol:&self.symbols[i]];
            }
            
            
        } else if (xref_options.objc_only) {
            
        } else {
            [self printSymbol:&self.symbols[i]];
        }
        
    }
}

- (void)dumpObjectiveCSymbols {
   struct segment_command_64 *sec = (struct segment_command_64 *)[self.sectionCommandsDictionary[@"__DATA.__objc_classlist"] pointerValue];
    
    int count = sec->vmsize / sizeof(void*);
    printf("counldt si");
}


- (void)dumpExternalSymbols {
    uintptr_t base = self.lazy_ptr_section->addr;
    size_t align_size = 1 << (self.lazy_ptr_section->align);
    for (int i = 0; i < self.indirect_symbols.count; i++) {
        int offset = self.indirect_symbols.indirect_sym[i];
        struct nlist_64 symbol = self.symbols[offset];
        int libIndex = GET_LIBRARY_ORDINAL(symbol.n_desc);
        char * chr = &self.str_symbols[symbol.n_un.n_strx];
        
        if (xref_options.verbose) {
            printf(" 0x%-8lx  %s%s%s: %s%-40s%s\n", base + (align_size * i), dcolor(DSCOLOR_YELLOW), [self.depdencies[libIndex] UTF8String], colorEnd(), dcolor(DSCOLOR_CYAN), chr, colorEnd() );
        } else {
            printf(" 0x%-8lx  %s%-40s%s\n", base + (align_size * i), dcolor(DSCOLOR_CYAN), chr, colorEnd() );
        }
    }
}


- (void)printSymbol:(struct nlist_64 *)sym {
    char * chr = &self.str_symbols[sym->n_un.n_strx];
    if (xref_options.objc_only && !strnstr(chr, "_OBJC_CLASS_$_", 14)) {
        return;
    }
    if (xref_options.objc_only) {
        chr += 14;
    }
    
    
    printf("0x%011llx ", sym->n_value);
    
    if (xref_options.verbose >= 2) {
        printf("%02x %02x %04x ", sym->n_type, sym->n_sect, sym->n_desc);
    }
    
    int libIndex = GET_LIBRARY_ORDINAL(sym->n_desc);
    
    if (xref_options.verbose >= 1) {
        if (sym->n_type & N_SECT && sym->n_sect) {
            struct section_64 * sec = ( struct section_64 * )self.sectionCommandsArray[sym->n_sect].longValue;
            printf("%s%s.%s%s ", dcolor(DSCOLOR_GRAY), sec->segname, sec->sectname, colorEnd());
        } else if (libIndex > 0 && (sym->n_type & N_TYPE) == N_UNDF) {
            const char *libName = [self.depdencies[libIndex] UTF8String];
            printf("%s%s%s: ", dcolor(DSCOLOR_YELLOW), libName, colorEnd());
        }
    }
    printf("%s%s%s \n", dcolor(DSCOLOR_CYAN), chr, colorEnd());
}

@end
