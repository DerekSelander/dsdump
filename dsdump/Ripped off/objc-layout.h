//
//  objc-layout.h
//  dsdump
//
//  Created by Derek Selander on 4/30/20.
//  Copyright © 2020 Selander. All rights reserved.
//

#ifndef objc_layout_h
#define objc_layout_h

 char *scan_ivar_type_for_layout(char *type, long offset, long bits_size, unsigned char *bits, long *next_offset);
 char *scan_basic_ivar_type(char *type, long *size, long *alignment, bool *is_reference);

 char *skip_ivar_type_name(char *type);
 char *skip_ivar_struct_name(char *type);

 char *scan_ivar_type_for_layout(char *type, long offset, long bits_size, unsigned char *bits, long *next_offset);
#endif /* objc_layout_h */
