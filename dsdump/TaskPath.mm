//
//  TaskPath.mm
//  xref
//
//  Created by Derek Selander on 5/7/19.
//  Copyright © 2019 Selander. All rights reserved.
//


#import <sys/proc_info.h>
#import <mach/mach.h>
#import <libproc.h>
#import <mach/mach_vm.h>
#import <libgen.h>
#import <mach-o/dyld_images.h>
#import <mach-o/loader.h>
#import <mach/mach.h>

extern "C" {

#import "miscellaneous.h"
BOOL FindLibraryInTask(pid_t task, pid_t pid, const char *search_string, uuid_t uuid, uint64_t *loadAddr, kern_return_t* err);
BOOL isUUIDMatch(task_t task, vm_address_t address, uuid_t uuid);

void DumpProcessesContainingLibrary(const char *lib_name, uuid_t uuid) {
    int pidcount = proc_listallpids(NULL, 0);
    int *all_pids = (int*)malloc(pidcount * sizeof(int));
    proc_listallpids(all_pids, pidcount);
    for (int i = 0; i < pidcount; i++) {
        pid_t pid = all_pids[i];
        task_t pid_task = TASK_NULL;
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &pid_task);
        
        if (kr != KERN_SUCCESS) { continue; }
        
        
        uint64 loadAddr = 0;
        if (!FindLibraryInTask(pid_task, pid, lib_name, uuid, &loadAddr, NULL)) { continue; }
        
        char buffer[PATH_MAX];
        proc_regionfilename(all_pids[i], 0, buffer, PATH_MAX);


        if (xref_options.verbose >= VERBOSE_1) {
            printf("%s0x%012llx%s ", dcolor(DSCOLOR_GRAY), loadAddr, color_end());
        }
        // TODO figure out basename bug, this gets screwed up on basename(buffer)...
        NSString *p;
        if (xref_options.verbose >= VERBOSE_2) {
            p = [NSString stringWithUTF8String:buffer];
        } else {
            p = [[NSString stringWithUTF8String:buffer] lastPathComponent];
        }
        
        
        printf("%s%d%s", dcolor(DSCOLOR_CYAN), all_pids[i], color_end());
        printf(" %s%s%s", dcolor(DSCOLOR_GREEN), [p UTF8String], color_end());
        putchar('\n');
    }
}


BOOL FindLibraryInTask(pid_t task, pid_t pid, const char *search_string, uuid_t uuid, uint64_t *loadAddr, kern_return_t* err) {
    
    kern_return_t kr = KERN_SUCCESS;
    if (loadAddr) { *loadAddr = 0; }
    
    task_dyld_info_data_t task_dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);
    if (kr != KERN_SUCCESS) {
        if (err) *err = kr;
        return NO;
    }
    
    if (task_dyld_info.all_image_info_addr  == MACH_VM_MIN_ADDRESS) {
        if (err) *err = -1;
        return NO;
    }
    
    if (task_dyld_info.all_image_info_size > sizeof(struct dyld_all_image_infos)) {
        if (err) *err = -1;
        return NO;
    }
    
    struct dyld_all_image_infos all_image_infos;
    mach_vm_size_t readSize = task_dyld_info.all_image_info_size;
    if ((kr = mach_vm_read_overwrite(task, task_dyld_info.all_image_info_addr, task_dyld_info.all_image_info_size, (vm_address_t)&all_image_infos, &readSize) ) != KERN_SUCCESS) {
        if (err) *err = kr;
        return NO;
    }
    
    // Die if lower than 15
    if (all_image_infos.version < 0xf) { return NO; }
    
    uint32_t imageCount = all_image_infos.infoArrayCount;
    size_t imageArraySize = imageCount * sizeof(dyld_image_info);
    dyld_image_info *imageArray64 = (dyld_image_info *)malloc(imageArraySize);
    if ((kr = ::mach_vm_read_overwrite(task, (mach_vm_address_t)all_image_infos.infoArray, imageArraySize, (vm_address_t)imageArray64, &readSize)) != KERN_SUCCESS ) {
        if (err) *err = kr;
        free(imageArray64);
        return NO;
    }
    
    for (int i = 0; i < imageCount; i++) {
        char path[PATH_MAX];
        
        // Just restart, there can be a bad addresses
        if (::mach_vm_read_overwrite(task, (mach_vm_address_t)imageArray64[i].imageFilePath, PATH_MAX, (vm_address_t)path, &readSize)) {
            continue;
        }
        
        // First checkk for the name of the string
        // If we got this far, let's go after the UUID
        // DYLD has a uuidArray, but that's only for non-shared cache modules
        if (strstr(path, search_string) && isUUIDMatch(task, (vm_address_t)imageArray64[i].imageLoadAddress, uuid)) {
            if (loadAddr) {
                *loadAddr = (uint64_t)imageArray64[i].imageLoadAddress;
            }
            free(imageArray64);
            return YES;
        }
    }
    
    // Just couldn't find it...
    if (err) *err = KERN_SUCCESS;
    free(imageArray64);
    return NO;
}

BOOL isUUIDMatch(task_t task, vm_address_t address, uuid_t uuid) {
    struct mach_header_64 header;
    mach_vm_size_t size = 0;
    if (::mach_vm_read_overwrite(task, address, sizeof(struct mach_header_64), (vm_address_t)&header, &size)) {
        return NO;
    }
    
    if (header.magic != MH_MAGIC_64) {
        pid_t pid = 0;
        pid_for_task(task, &pid);
        warn_debug("Didn't find a 0xfeedfacf in %d, %p\n", pid, address);
        return NO;
    }
    
    uintptr_t *pointer = (uintptr_t*)malloc(header.sizeofcmds);
    if (::mach_vm_read_overwrite(task, address, header.sizeofcmds, (vm_address_t)pointer, &size)) {
        return NO;
    }
    uintptr_t cur = (((uintptr_t)pointer) + sizeof(mach_header_64));
    for (int i = 0; i < header.ncmds; i++) {
        load_command *cmd = (load_command *)cur;
        if (cmd->cmd == LC_UUID) {
            struct uuid_command* uuid_cmd = (struct uuid_command*)cur;
            if (strncmp((const char*)&uuid_cmd->uuid, (const char*)uuid, 16) == 0) {
                return YES;
            }
            
        }
        cur += cmd->cmdsize;
    }
    
    return NO;
}

} // extern "C" {
