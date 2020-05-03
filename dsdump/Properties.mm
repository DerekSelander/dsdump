//
//  Properties.cpp
//  dsdump
//
//  Created by Derek Selander on 4/28/20.
//  Copyright © 2020 Selander. All rights reserved.
//

#include "Properties.h"

static const char * kPropertyType = "T";
static const char * kPropertyOverridenGetter = "G";
static const char * kPropertyOverridenSetter = "S";
static const char * kPropertyIsReadOnly = "R";
static const char * kPropertyIsNonatomic = "N";
static const char * kPropertyIsAtomic = "A";
static const char * kPropertyIsStrong = "&";
static const char * kPropertyIsWeak = "W";
static const char * kPropertyIVarName = "V";

char *copyPropertyAttributeValue(const char *attrs, const char *name);

static objc_property_attribute_t *
copyPropertyAttributeList(const char *attrs, unsigned int *outCount);
/********************************************************************************
 // Properties
 ********************************************************************************/

static void printType(const char *type) {
    if (!type) {
        return;
    }
    
    auto length = strlen(type);
    
    // First check if it looks like an ObjC class i.e. T=@"NSObject"
    if (length > 3 && type[0] == '@' && type[1] == '"' && type[length - 1] == '"') {
        printf(" %.*s *", (int)(length-3), (type+2));
    }
    
    int pointerCount = 0;
    for (int i = 0; i < strlen(type); i++) {
//        if (type[i] == 'i')
    }
}

static void printPropertyAttributeTypes(const char *propertyAttributes) {
    printf("\t%s@property %s", dcolor(DSCOLOR_GREEN), color_end());
    if (xref_options.verbose < VERBOSE_4) {
         return;
     }
    auto type = copyPropertyAttributeValue(propertyAttributes, kPropertyType);
    auto ivarName = copyPropertyAttributeValue(propertyAttributes, kPropertyIVarName);
    
    unsigned int outCount = 0;
    auto attrs = copyPropertyAttributeList(propertyAttributes, &outCount);
    if (outCount > 1 && strcmp(attrs[outCount -1].name, "V")==0) {
        outCount--;
    }

    // Assuming the T (type) attribute is always around...
    if (outCount > 1) {
        printf("(");
        
        // Start at 1, skip the type...
        for (int i = 1; i < outCount; i++) {
            auto attribute = attrs[i];
            if (strcmp(attribute.name, kPropertyIsStrong) == 0) {
                printf("strong");
            } else if (strcmp(attribute.name, kPropertyIsNonatomic) == 0) {
                printf("nonatomic");
            } else if (strcmp(attribute.name, kPropertyIsWeak) == 0) {
                printf("weak");
            } else if (strcmp(attribute.name, kPropertyIsReadOnly) == 0) {
                printf("readonly");
            } else if (strcmp(attribute.name, kPropertyOverridenGetter) == 0) {
                printf("getter=%s", attribute.value);
            } else if (strcmp(attribute.name, kPropertyOverridenSetter) == 0) {
                printf("setter=%s", attribute.value);
            } else if (strcmp(attribute.name, kPropertyIsAtomic) == 0) {
                printf("atomic");
            }
            if (i != outCount - 1) {
                printf(", ");
            }
            
        }
        printf(")");
    }
    free(attrs);
    
    printType(type);
    
    
}
#import "objc-layout.h"
static void printProperty(property_t property) {
    auto propertyName = property.name->disk();
    auto propertyAttributes = property.attributes->disk();
    printPropertyAttributeTypes(propertyAttributes);
    printf("%s%s%s\n", dcolor(DSCOLOR_BOLD), propertyName, color_end());
}

void dumpObjCPropertiesWithResolvedAddress(property_list_t* propertiesList) {
    if (xref_options.verbose < VERBOSE_4) {
        return;
    }
    
    if (propertiesList == nullptr) {
        return;
    }
    
    auto propertiesListDisk = propertiesList->disk();
    auto count = propertiesListDisk->count;
    auto properties = &propertiesListDisk->first_property;
    if (properties == nullptr) {
        return;
    }
    
    for (int i = 0; i < count; i++) {
        auto property = properties[i];
        auto propertyName = property.name->disk();
        auto propertyAttributes = property.attributes->disk();
        printProperty(property);
        
        printf("%s %s\n", propertyAttributes, skip_ivar_type_name((char*)propertyAttributes));
//        scan_ivar_type_for_layout(propertyAttributes, 0, 0, <#unsigned char *bits#>, <#long *next_offset#>)
        /*
        static char *scan_ivar_type_for_layout(char *type, long offset, long bits_size, unsigned char *bits, long *next_offset);
        static char *scan_basic_ivar_type(char *type, long *size, long *alignment, bool *is_reference);

        static char *skip_ivar_type_name(char *type);
        static char *skip_ivar_struct_name(char *type);

        static char *scan_ivar_type_for_layout(char *type, long offset, long bits_size, unsigned char *bits, long *next_offset);
        */
    }
    
    if (count) {
        putchar('\n');
    }
}

void dumpObjCPropertiesWithResolvedAddress(swift_class* cls) {
    if (xref_options.verbose < VERBOSE_4) {
        return;
    }
    
    auto clsDisk = cls->disk();
    auto rodata = clsDisk->rodata();
    if (rodata == nullptr) {
        return;
    }
    
    auto propertiesList = rodata->disk()->baseProperties;
    dumpObjCPropertiesWithResolvedAddress(propertiesList);
}

void dumpObjCPropertiesWithResolvedAddress(protocol_t* prtl) {
    if (xref_options.verbose < VERBOSE_4) {
        return;
    }
    auto properties = prtl->disk()->instanceProperties;
    if (properties == nullptr) {
        return;
    }
    dumpObjCPropertiesWithResolvedAddress(properties->disk());
}



//////////////////////


static unsigned int
iteratePropertyAttributes(const char *attrs,
                          bool (*fn)(unsigned int index,
                                     void *ctx1, void *ctx2,
                                     const char *name, size_t nlen,
                                     const char *value, size_t vlen),
                          void *ctx1, void *ctx2)
{
    if (!attrs) return 0;

    unsigned int attrcount = 0;

    while (*attrs) {
        // Find the next comma-separated attribute
        const char *start = attrs;
        const char *end = start + strcspn(attrs, ",");

        // Move attrs past this attribute and the comma (if any)
        attrs = *end ? end+1 : end;

        
        // Skip empty attribute
        if (start == end) continue;

        // Process one non-empty comma-free attribute [start,end)
        const char *nameStart;
        const char *nameEnd;

      
        if (*start != '\"') {
            // single-char short name
            nameStart = start;
            nameEnd = start+1;
            start++;
        }
        else {
            // double-quoted long name
            nameStart = start+1;
            nameEnd = nameStart + strcspn(nameStart, "\",");
            start++;                       // leading quote
            start += nameEnd - nameStart;  // name
            if (*start == '\"') start++;   // trailing quote, if any
        }

        // Process one possibly-empty comma-free attribute value [start,end)
        const char *valueStart;
        const char *valueEnd;

  

        valueStart = start;
        valueEnd = end;

        bool more = (*fn)(attrcount, ctx1, ctx2,
                          nameStart, nameEnd-nameStart,
                          valueStart, valueEnd-valueStart);
        attrcount++;
        if (!more) break;
    }

    return attrcount;
}


static bool
copyOneAttribute(unsigned int index, void *ctxa, void *ctxs,
                 const char *name, size_t nlen, const char *value, size_t vlen)
{
    objc_property_attribute_t **ap = (objc_property_attribute_t**)ctxa;
    char **sp = (char **)ctxs;

    objc_property_attribute_t *a = *ap;
    char *s = *sp;

    a->name = s;
    memcpy(s, name, nlen);
    s += nlen;
    *s++ = '\0';
    
    a->value = s;
    memcpy(s, value, vlen);
    s += vlen;
    *s++ = '\0';

    a++;
    
    *ap = a;
    *sp = s;

    return YES;
}

                 
objc_property_attribute_t *
copyPropertyAttributeList(const char *attrs, unsigned int *outCount)
{
    if (!attrs) {
        if (outCount) *outCount = 0;
        return nil;
    }

    // Result size:
    //   number of commas plus 1 for the attributes (upper bound)
    //   plus another attribute for the attribute array terminator
    //   plus strlen(attrs) for name/value string data (upper bound)
    //   plus count*2 for the name/value string terminators (upper bound)
    unsigned int attrcount = 1;
    const char *s;
    for (s = attrs; s && *s; s++) {
        if (*s == ',') attrcount++;
    }

    size_t size =
        attrcount * sizeof(objc_property_attribute_t) +
        sizeof(objc_property_attribute_t) +
        strlen(attrs) +
        attrcount * 2;
    objc_property_attribute_t *result = (objc_property_attribute_t *)
        calloc(size, 1);

    objc_property_attribute_t *ra = result;
    char *rs = (char *)(ra+attrcount+1);

    attrcount = iteratePropertyAttributes(attrs, copyOneAttribute, &ra, &rs);

    

    if (attrcount == 0) {
        free(result);
        result = nil;
    }

    if (outCount) *outCount = attrcount;
    return result;
}


static bool
findOneAttribute(unsigned int index, void *ctxa, void *ctxs,
                 const char *name, size_t nlen, const char *value, size_t vlen)
{
    const char *query = (char *)ctxa;
    char **resultp = (char **)ctxs;

    if (strlen(query) == nlen  &&  0 == strncmp(name, query, nlen)) {
        char *result = (char *)calloc(vlen+1, 1);
        memcpy(result, value, vlen);
        result[vlen] = '\0';
        *resultp = result;
        return NO;
    }

    return YES;
}

char *copyPropertyAttributeValue(const char *attrs, const char *name)
{
    char *result = nil;

    iteratePropertyAttributes(attrs, findOneAttribute, (void*)name, &result);

    return result;
}

