//
//  DSXRLibrary+SymbolDumper.h
//  xref
//
//  Created by Derek Selander on 4/22/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "DSXRLibrary.h"

NS_ASSUME_NONNULL_BEGIN

@interface DSXRLibrary (SymbolDumper)
- (void)dumpSymbols;
- (void)dumpObjectiveCSymbols;
- (void)dumpExternalSymbols;

- (void)printSymbol:(struct nlist_64 *)sym;
@end

NS_ASSUME_NONNULL_END
