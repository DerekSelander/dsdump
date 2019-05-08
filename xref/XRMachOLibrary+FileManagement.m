//
//  XRMachOLibrary+FileManagement.m
//  xref
//
//  Created by Derek Selander on 4/10/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary.h"
#import <sys/mman.h>

//#define PAYLOAD_FILE_SIZE(c)  (sizeof(long) + (sizeof(cs_insn) * (c)) + (sizeof(cs_detail) * (c)))


@implementation XRMachOLibrary (FileManagement)


////////////////////////////////////////////////////////////////
// Public methods
////////////////////////////////////////////////////////////////

/// Generates the data, you might want to redesign this if you want to parse multiple frameworks
// currently only does one, so dispatch_once logic might be over the top
- (BOOL)parseData {
    static dispatch_once_t onceToken;
    static BOOL done = NO;
    dispatch_once(&onceToken, ^{
        struct section_64* text_section = [self.sectionCommandsDictionary[@"__TEXT.__text"] pointerValue];
        if (!text_section) {
            done = NO;
        } else {
            done = [self parseDataOnDisk];
        }
    });

    

    // This is for the --analyze option, not implemented yet
//    size_t count = 0;
//    cs_insn *instructions = [self loadInstructionsIfAvailable:&count];
//    if (instructions) {
//        self.instructions = instructions;
//        self.instructions_count = count;
//        return YES;
//    }
    
    return done;
}

/// Will save the instructions to disk
-(BOOL)saveInstructions:(cs_insn *)instructions count:(size_t)count {

    BOOL success = YES;
    int fd = open([[self analysisSavePath] UTF8String], O_RDWR|O_CREAT|O_TRUNC, 0666);
    if (fd == -1) {
        success = NO;
        perror("file access error...\n");
        return NO;
    }
    
    cs_detail *buffer = calloc(count, sizeof(*buffer));
    printf("memcpy...\n");
    BOOL isATerminal = isatty(STDERR_FILENO);

    if (isATerminal) {
//        progress = progressbar_new("Processing... ", 100);
    }
    long iterator = count / 100;
    long prog = 0;
    for (int i = 0; i < count; i++) {
        if (instructions[i].detail) {
            memcpy(&buffer[i], instructions[i].detail, sizeof(cs_detail));
        } else {
            printf("no detail: %p\n", (void*)instructions[i].address);
        }
        
        if (isATerminal && i >= prog) {
            prog += iterator;
//            progressbar_inc(progress);
        }
    }
//    if (isATerminal) { progressbar_finish(progress); }
    printf("memcpy finished...\n");
    
    printf("write1...\n");
    if (pwrite(fd, &count, sizeof(long), 0) == -1) {
        success = NO;
    }
    printf("write2...\n");
    if (pwrite(fd, instructions, sizeof(cs_insn) * count, sizeof(long)) == -1) {
        success = NO;
    }
    printf("write3...\n");
    if (pwrite(fd, buffer, sizeof(cs_detail) * count, sizeof(long) + sizeof(cs_insn) * count) == -1) {
        
        success = NO;
    }
    
    if (fd) {
        close(fd);
    }

    return YES;
}

////////////////////////////////////////////////////////////////
// Private methods
////////////////////////////////////////////////////////////////

- (BOOL)parseDataOnDisk {

    cs_arch arch = self.header.cputype == CPU_TYPE_ARM64? CS_ARCH_ARM64 : CS_ARCH_X86;
    cs_mode mode = self.header.cputype == CPU_TYPE_ARM64? CS_MODE_ARM : CS_MODE_64;
    csh handle = 0;
    
    int err = cs_open(arch, mode, &handle);
    if (err != CS_ERR_OK) { assert(NO); }
    
    //    struct platform platforms;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    struct section_64* text_section = [self.sectionCommandsDictionary[@"__TEXT.__text"] pointerValue];
    if (!text_section) { return NO; }
    
    void *buffer = calloc(text_section->size, sizeof(char));
    pread(self.fd, buffer, text_section->size, text_section->offset + self.file_offset);
    
    
    cs_insn *instructions = NULL;
//    printf("parsing instructions on disk...\n");
    size_t count = cs_disasm(handle, buffer,                                                                               text_section->size, text_section->addr, 0, &instructions);
    
    
    if (xref_options.analyze) {
//        printf("Analyzing...\n");
        if ([self saveInstructions:instructions count:count] == NO) {
            perror("Save error\n");
            exit(1);
        }
//        printf("finished...\n");
    }
    
    self.instructions = instructions;
    self.instructions_count = count;

    
    cs_close(&handle);
    return YES;
}

/// Looks into /tmp/com.selander.xref.whatever for local data
-(cs_insn *)loadInstructionsIfAvailable:(size_t *)c {
    const char *filePath = [[self analysisSavePath] UTF8String];
    
    int fd = open(filePath, O_RDONLY);
    if (fd == -1) {
        if (c) { *c = 0; }
        return NULL;

    }
    
    size_t count = 0;
    pread(self.fd, &count, sizeof(long), 0);
    
    cs_insn *instructions = calloc(count, sizeof(cs_insn));
    pread(self.fd, instructions, sizeof(cs_insn) * count, sizeof(long));
    
    cs_detail *deets = calloc(count, sizeof(cs_detail));
    pread(self.fd, deets, sizeof(cs_detail) * count, sizeof(long) + sizeof(cs_insn) * count);
    for (int i = 0; i < count; i++) {
        cs_insn insn = instructions[i];
        if (insn.detail) {
            insn.detail = &deets[i];
        }
        else {
            printf("da fuck\n");
        }
    }
    
    if (c) { *c = count; }
    return instructions;
}

- (NSString *)translateUUID {
    char uuid_output[37];
    for (int cur = 0, i = 0; i < 16; i++) {
        char c = self.uuid_cmd->uuid[i];
        char lower = c & 0xf;
        char upper = (c & 0xf0) >> 4;
        
        if (upper < 10) {
            upper += 48;
        } else {
            upper += 55;
        }
        
        if (lower < 10) {
            lower += 48;
        } else {
            lower += 55;
        }
        uuid_output[cur++] = upper;
        uuid_output[cur++] = lower;
        if (i == 3 || i == 5 || i == 7 || i == 9) {
            uuid_output[cur++] = '-';
        }
        uuid_output[cur] = '\x00';
    }
    
    return [NSString stringWithUTF8String:uuid_output];
}

- (NSString *)analysisSavePath {
    return [NSString stringWithFormat:@"/tmp/com.selander.xref.%@", [self translateUUID]];
}


@end




