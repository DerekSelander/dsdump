//
//  DSXRLibrary+FileManagement.h
//  xref
//
//  Created by Derek Selander on 4/10/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "DSXRLibrary.h"

NS_ASSUME_NONNULL_BEGIN

@interface DSXRLibrary (FileManagement)
-(BOOL)saveFile;
-(BOOL)loadFileIfAvailable;
@end

NS_ASSUME_NONNULL_END
