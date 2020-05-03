/*
 * Copyright (c) 2004-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <stdlib.h>
#include <assert.h>
#import <Foundation/Foundation.h>
//#include "objc-private.h"

/**********************************************************************
* Object Layouts.
*
* Layouts are used by the garbage collector to identify references from
* the object to other objects.
* 
* Layout information is in the form of a '\0' terminated byte string. 
* Each byte contains a word skip count in the high nibble and a
* consecutive references count in the low nibble. Counts that exceed 15 are
* continued in the succeeding byte with a zero in the opposite nibble. 
* Objects that should be scanned conservatively will have a NULL layout.
* Objects that have no references have a empty byte string.
*
* Example;
* 
*   For a class with pointers at offsets 4,12, 16, 32-128
*   the layout is { 0x11, 0x12, 0x3f, 0x0a, 0x00 } or
*       skip 1 - 1 reference (4)
*       skip 1 - 2 references (12, 16)
*       skip 3 - 15 references (32-88)
*       no skip - 10 references (92-128)
*       end
* 
**********************************************************************/


/**********************************************************************
* compress_layout
* Allocates and returns a compressed string matching the given layout bitmap.
**********************************************************************/
static unsigned char *
compress_layout(const uint8_t *bits, size_t bitmap_bits, bool weak)
{
    bool all_set = YES;
    bool none_set = YES;
    unsigned char *result;

    // overallocate a lot; reallocate at correct size later
    unsigned char * const layout = (unsigned char *)
        calloc(bitmap_bits + 1, 1);
    unsigned char *l = layout;

    size_t i = 0;
    while (i < bitmap_bits) {
        size_t skip = 0;
        size_t scan = 0;

        // Count one range each of skip and scan.
        while (i < bitmap_bits) {
            uint8_t bit = (uint8_t)((bits[i/8] >> (i % 8)) & 1);
            if (bit) break;
            i++;
            skip++;
        }
        while (i < bitmap_bits) {
            uint8_t bit = (uint8_t)((bits[i/8] >> (i % 8)) & 1);
            if (!bit) break;
            i++;
            scan++;
            none_set = NO;
        }

        // Record skip and scan
        if (skip) all_set = NO;
        if (scan) none_set = NO;
        while (skip > 0xf) {
            *l++ = 0xf0;
            skip -= 0xf;
        }
        if (skip || scan) {
            *l = (uint8_t)(skip << 4);    // NOT incremented - merges with scan
            while (scan > 0xf) {
                *l++ |= 0x0f;  // May merge with short skip; must calloc
                scan -= 0xf;
            }
            *l++ |= scan;      // NOT checked for zero - always increments
                               // May merge with short skip; must calloc
        }
    }
    
    // insert terminating byte
    *l++ = '\0';
    
    // return result
    if (none_set  &&  weak) {
        result = NULL;  // NULL weak layout means none-weak
    } else if (all_set  &&  !weak) {
        result = NULL;  // NULL ivar layout means all-scanned
    } else {
        result = (unsigned char *)strdup((char *)layout); 
    }
    free(layout);
    return result;
}


// emacs autoindent hack - it doesn't like the loop in set_bits/clear_bits
#if 0
} }
#endif


#define _C_ID       '@'
#define _C_CLASS    '#'
#define _C_SEL      ':'
#define _C_CHR      'c'
#define _C_UCHR     'C'
#define _C_SHT      's'
#define _C_USHT     'S'
#define _C_INT      'i'
#define _C_UINT     'I'
#define _C_LNG      'l'
#define _C_ULNG     'L'
#define _C_LNG_LNG  'q'
#define _C_ULNG_LNG 'Q'
#define _C_FLT      'f'
#define _C_DBL      'd'
#define _C_BFLD     'b'
#define _C_BOOL     'B'
#define _C_VOID     'v'
#define _C_UNDEF    '?'
#define _C_PTR      '^'
#define _C_CHARPTR  '*'
#define _C_ATOM     '%'
#define _C_ARY_B    '['
#define _C_ARY_E    ']'
#define _C_UNION_B  '('
#define _C_UNION_E  ')'
#define _C_STRUCT_B '{'
#define _C_STRUCT_E '}'
#define _C_VECTOR   '!'
#define _C_CONST    'r'

// The code below may be useful when interpreting ivar types more precisely.

/**********************************************************************
* mark_offset_for_layout
*
* Marks the appropriate bit in the bits array cooresponding to a the
* offset of a reference.  If we are scanning a nested pointer structure
* then the bits array will be NULL then this function does nothing.  
* 
**********************************************************************/
 void mark_offset_for_layout(long offset, long bits_size, unsigned char *bits) {
    // references are ignored if bits is NULL
    if (bits) {
        long slot = offset / sizeof(long);
        
        // determine byte index using (offset / 8 bits per byte)
        long i_byte = slot >> 3;
        
        // if the byte index is valid 
        if (i_byte < bits_size) {
            // set the (offset / 8 bits per byte)th bit
            bits[i_byte] |= 1 << (slot & 7);
        } else {
            // offset not within instance size
            //_objc_inform ("layout - offset exceeds instance size");
        }
    }
}

/**********************************************************************
* skip_ivar_type_name
*
* Skip over the name of a field/class in an ivar type string.  Names
* are in the form of a double-quoted string.  Returns the remaining
* string.
*
**********************************************************************/
 char *skip_ivar_type_name(char *type) {
    // current character
    char ch;
    
    // if there is an open quote
    if (*type == '\"') {
        // skip quote
        type++;
        
        // while no closing quote
        while ((ch = *type) != '\"') {
            // if end of string return end of string
            if (!ch) return type;
            
            // skip character
            type++;
        }
        
        // skip closing quote
        type++;
    }
    
    // return remaining string
    return type;
}


/**********************************************************************
* skip_ivar_struct_name
*
* Skip over the name of a struct in an ivar type string.  Names
* may be followed by an equals sign.  Returns the remaining string.
*
**********************************************************************/
 char *skip_ivar_struct_name(char *type) {
    // get first character
    char ch = *type;
    
    if (ch == _C_UNDEF) {
        // skip undefined name 
        type++;
    } else if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_') {
        // if alphabetic
        
        // scan alphanumerics
        do {
            // next character
            ch = *++type;
        } while ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || (ch >= '0' && ch <= '9'));
    } else {
        // no struct name present
        return type;
    }
    
    // skip equals sign
    if (*type == '=') type++;
    
    return type;
}


/**********************************************************************
* scan_basic_ivar_type
* 
* Determines the size and alignment of a basic ivar type.  If the basic
* type is a possible reference to another garbage collected type the 
* is_reference is set to true (false otherwise.)  Returns the remaining
* string.
* 
**********************************************************************/
 char *scan_ivar_type_for_layout(char *type, long offset, long bits_size, unsigned char *bits, long *next_offset);
 char *scan_basic_ivar_type(char *type, long *size, long *alignment, bool *is_reference) {
    // assume it is a non-reference type
    *is_reference = NO;
    
    // get the first character (advancing string)
    const char *full_type = type;
    char ch = *type++;
    
    // GCC 4 uses for const type*.
    if (ch == _C_CONST) ch = *type++;
    
    // act on first character
    switch (ch) {
        case _C_ID: {
            // ID type
            
            // skip over optional class name
            type = skip_ivar_type_name(type);
            
            // size and alignment of an id type
            *size = sizeof(id);
            *alignment = __alignof(id);
            
            // is a reference type
            *is_reference = YES;
            break;
        }        
        case _C_PTR: {
            // C pointer type
            
            // skip underlying type
            long ignored_offset;
            type = scan_ivar_type_for_layout(type, 0, 0, NULL, &ignored_offset);
            
            // size and alignment of a generic pointer type
            *size = sizeof(void *);
            *alignment = __alignof(void *);
            
            // is a reference type
            *is_reference = YES;
            break;
        }
        case _C_CHARPTR: {
            // C string 
            
           // size and alignment of a char pointer type
            *size = sizeof(char *);
            *alignment = __alignof(char *);
            
            // is a reference type
            *is_reference = YES;
            break;
        }
        case _C_CLASS:
        case _C_SEL: {
            // classes and selectors are ignored for now
            *size = sizeof(void *);
            *alignment = __alignof(void *);
            break;
        }
        case _C_CHR:
        case _C_UCHR: {
            // char and unsigned char
            *size = sizeof(char);
            *alignment = __alignof(char);
            break;
        }
        case _C_SHT:
        case _C_USHT: {
            // short and unsigned short
            *size = sizeof(short);
            *alignment = __alignof(short);
            break;
        }
        case _C_ATOM:
        case _C_INT:
        case _C_UINT: {
            // int and unsigned int
            *size = sizeof(int);
            *alignment = __alignof(int);
            break;
        }
        case _C_LNG:
        case _C_ULNG: {
            // long and unsigned long
            *size = sizeof(long);
            *alignment = __alignof(long);
            break;
        }
        case _C_LNG_LNG:
        case _C_ULNG_LNG: {
            // long long and unsigned long long
            *size = sizeof(long long);
            *alignment = __alignof(long long);
            break;
        }
        case _C_VECTOR: {
            // vector
            *size = 16;
            *alignment = 16;
            break;
        }
        case _C_FLT: {
            // float
            *size = sizeof(float);
            *alignment = __alignof(float);
            break;
        }
        case _C_DBL: {
            // double
            *size = sizeof(double);
            *alignment = __alignof(double);
            break;
        }
        case _C_BFLD: {
            // bit field
            
            // get number of bits in bit field (advance type string)
            long lng = strtol(type, &type, 10);
            
            // while next type is a bit field
            while (*type == _C_BFLD) {
                // skip over _C_BFLD
                type++;
                
                // get next bit field length
                long next_lng = strtol(type, &type, 10);
                
                // if spans next word then align to next word
                if ((lng & ~31) != ((lng + next_lng) & ~31)) lng = (lng + 31) & ~31;
                
                // increment running length
                lng += next_lng;
                
                // skip over potential field name
                type = skip_ivar_type_name(type);
            }
            
            // determine number of bytes bits represent
            *size = (lng + 7) / 8;
            
            // byte alignment
            *alignment = __alignof(char);
            break;
        }
        case _C_BOOL: {
            // double
            *size = sizeof(BOOL);
            *alignment = __alignof(BOOL);
            break;
        }
        case _C_VOID: {
            // skip void types
            *size = 0;
            *alignment = __alignof(char);
            break;
        }
        case _C_UNDEF: {
            *size = 0;
            *alignment = __alignof(char);
            break;
        }
        default: {
            // unhandled type
            //_objc_fatal("unrecognized character \'%c\' in ivar type: \"%s\"", ch, full_type);
        }
    }
    
    return type;
}


/**********************************************************************
* scan_ivar_type_for_layout
*
* Scan an ivar type string looking for references.  The offset indicates
* where the ivar begins.  bits is a byte array of size bits_size used to
* contain the references bit map.  next_offset is the offset beyond the
* ivar.  Returns the remaining string.
*
**********************************************************************/
 char *scan_ivar_type_for_layout(char *type, long offset, long bits_size, unsigned char *bits, long *next_offset) {
    long size;                                   // size of a basic type
    long alignment;                              // alignment of the basic type
    bool is_reference;                      // true if the type indicates a reference to a garbage collected object
    
    // get the first character
    char ch = *type;

    // GCC 4 uses for const type*.
    if (ch == _C_CONST) ch = *++type;
    
    // act on first character
    switch (ch) {
        case _C_ARY_B: {
            // array type
            
            // get the array length
            long lng = strtol(type + 1, &type, 10);
            
            // next type will be where to advance the type string once the array is processed
            char *next_type = type;
           
            // repeat the next type x lng
            if (!lng) {
                next_type = scan_ivar_type_for_layout(type, 0, 0, NULL, &offset);
            } else {
                while (lng--) {
                    // repeatedly scan the same type
                    next_type = scan_ivar_type_for_layout(type, offset, bits_size, bits, &offset);
                }
            }
            
            // advance the type now
            type = next_type;
            
            // after the end of the array
            *next_offset = offset;
            
            // advance over closing bracket
            if (*type == _C_ARY_E) type++;
            //else                   _objc_inform("missing \'%c\' in ivar type.", _C_ARY_E);
            
            break;
        }
        case _C_UNION_B: {
            // union type
            
            // skip over possible union name
            type = skip_ivar_struct_name(type + 1); 
            
            // need to accumulate the maximum element offset
            long max_offset = 0;
        
            // while not closing paren
            while ((ch = *type) && ch != _C_UNION_E) {
                // skip over potential field name
                type = skip_ivar_type_name(type);
                
                // scan type
                long union_offset;
                type = scan_ivar_type_for_layout(type, offset, bits_size, bits, &union_offset);
                
                // adjust the maximum element offset
                if (max_offset < union_offset) max_offset = union_offset;
            }
        
            // after the largest element 
            *next_offset = max_offset;
            
            // advance over closing paren
            if (ch == _C_UNION_E) {
              type++;
            } else {
//              _objc                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  _inform("missing \'%c\' in ivar type", _C_UNION_E);
            }
            
            break;
        }
        case _C_STRUCT_B: {
            // struct type
            
            // skip over possible struct name
            type = skip_ivar_struct_name(type + 1); 
            
            // while not closing brace
            while ((ch = *type) && ch != _C_STRUCT_E) {
                // skip over potential field name
                type = skip_ivar_type_name(type);
                
                // scan type
                type = scan_ivar_type_for_layout(type, offset, bits_size, bits, &offset);
            }
            
            // after the end of the struct
            *next_offset = offset;
            
            // advance over closing brace
            if (ch == _C_STRUCT_E) type++;
//            else                   _objc_inform("missing \'%c\' in ivar type", _C_STRUCT_E);
            
            break;
        }
        default: {
            // basic type
            
            // scan type
            type = scan_basic_ivar_type(type, &size, &alignment, &is_reference);
            
            // create alignment mask
            alignment--; 
            
            // align offset
            offset = (offset + alignment) & ~alignment;
            
            // if is a reference then mark in the bit map
            if (is_reference) mark_offset_for_layout(offset, bits_size, bits);
            
            // after the basic type
            *next_offset = offset + size;
            break;
        }
    }
    
    // return remainder of type string
    return type;
}
