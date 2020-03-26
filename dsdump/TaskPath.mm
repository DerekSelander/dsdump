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
#import <mach/mach.h>

extern "C" {

#import "miscellaneous.h"
BOOL FindLibraryInTask(pid_t task, pid_t pid, const char *search_string, uint64_t *loadAddr, kern_return_t* err);
    
void DumpProcessesContainingLibrary(const char *lib_name) {
    int pidcount = proc_listallpids(NULL, 0);
    int *all_pids = (int*)malloc(pidcount * sizeof(int));
    proc_listallpids(all_pids, pidcount);
    for (int i = 0; i < pidcount; i++) {
        pid_t pid = all_pids[i];
        task_t pid_task = TASK_NULL;
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &pid_task);
        
        if (kr != KERN_SUCCESS) { continue; }
        
        
        uint64 loadAddr = 0;
        if (!FindLibraryInTask(pid_task, pid, lib_name, &loadAddr, NULL)) { continue; }
        
        char buffer[PATH_MAX];
        proc_regionfilename(all_pids[i], 0, buffer, PATH_MAX);


        if (xref_options.verbose >= VERBOSE_2) {
            printf("0x%011llx ", loadAddr);
        }
        // TODO figure out basename bug, this gets screwed up on basename(buffer)...
        NSString *p;
        if (xref_options.verbose == VERBOSE_NONE) {
            p = [[NSString stringWithUTF8String:buffer] lastPathComponent];
        } else {
            p = [NSString stringWithUTF8String:buffer];
        }
        
        
        printf("%s%d%s", dcolor(DSCOLOR_CYAN), all_pids[i], color_end());
        printf(" %s%s%s", dcolor(DSCOLOR_GREEN), [p UTF8String], color_end());
        putchar('\n');
    }
}


BOOL FindLibraryInTask(pid_t task, pid_t pid, const char *search_string, uint64_t *loadAddr, kern_return_t* err) {
    
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
        return NO;
    }
    
    for (int i = 0; i < imageCount; i++) {
        char path[PATH_MAX];
        // Just restart, there can be a bad addresses
        if (::mach_vm_read_overwrite(task, (mach_vm_address_t)imageArray64[i].imageFilePath, PATH_MAX, (vm_address_t)path, &readSize)) {
            continue;
        }
        if (strstr(path, search_string)) {
            if (err) *err = kr;
            if (loadAddr) {
                *loadAddr = (uint64_t)imageArray64[i].imageLoadAddress;
            }
            return YES;
        }
    }

    // Just couldn't find it...
    if (err) *err = KERN_SUCCESS;
    return NO;
}


}
