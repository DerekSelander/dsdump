//
//  XRMachOLibrary+PID_Info.m
//  xref
//
//  Created by Derek Selander on 5/3/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary+PID_Info.h"
#import <Foundation/Foundation.h>
#import <sys/proc.h>
#import <sys/proc_info.h>
#import <mach/mach.h>
#import <sys/proc_info.h>
#import <libproc.h>
#import <mach/vm_region.h>
#import <mach/bootstrap.h>
#include <libgen.h>
#include <dlfcn.h>
//#include "dyld_process_info_internal.h"

@implementation XRMachOLibrary (PID_Info)




void getRegions(task_t pid_task, mach_vm_address_t *address) {
    
//    getNames(pid_task);
//    mach_vm_address_t a_addr = 0;
//    struct proc_regionwithpathinfo regioninfo;
//    mach_vm_address_t address = 0;
    
//    vm_info_region_64_t region;
//    mach_msg_type_number_t objectsCnt = 0;
    mach_vm_size_t size = 0;
//    task_t pid_task;
  
    pid_t pid;
    pid_for_task(pid_task,  &pid);

    vm_region_submap_short_info_data_64_t submap_info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t depth = 9999; // vmmap does this so, why not...
    
    
//    if (!depth) {
//        depth = &d;
//    }
//    mach_vm_purgable_control(<#vm_map_t target_task#>, <#mach_vm_address_t address#>, vm_purgable_t control, <#int *state#>)
    //    proc_pidinfo
    //    kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a_addr, &size, &depth, &submap_info, &count);
    while ((KERN_SUCCESS == mach_vm_region_recurse(pid_task, address, &size, &depth, (vm_region_recurse_info_64_t)&submap_info, &count))) {
        
        assert(count == 0xc);
        
//        if (submap_info.share_mode == SM_TRUESHARED) {
//            printf("yay shared\n");
//        }
        
//        if (submap_info.user_tag <= VM_MEMORY_MALLOC_LARGE_REUSED) {
//            *address += size;
//            continue;
//        }
//        if (*address <= glob_addr && glob_addr <= (*address + size)) {
//            printf("yay");
//        }
        
     
        
//        printf("submap %d\n", submap_info.is_submap);
        
        // Da fuk? is_submap doesn't match output, should this be packed or a legit Apple bug?
//        if ((long)submap_info.is_submap > 0) {
//        if (submap_info.is_submap) {
//            printf("submap %x !\n", submap_info.is_submap);
//            mach_vm_address_t tmp_addr = *address;
////            getRegions(pid_task, &tmp_addr);
//        }

        struct proc_regionwithpathinfo reginfo;
        __unused int retval = proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, *address, &reginfo, sizeof(struct proc_regionwithpathinfo));
        printf("%*s%016llx-%016llx tag: %x %s\n", depth * 4, "", *address, *address + size, submap_info.user_tag, (reginfo.prp_vip.vip_path));
//        depth = 9999;
//        depth++;
        if (submap_info.is_submap) {
            depth++;
//            depth = 9999;
        } else {
            (*address) += size;
        }
        size = 0;
        
//        if (addr <= glob_addr && glob_addr <= addr + size) {
//            printf("yay");
//        }
//        printf("%.*s0x%08llx - 0x%08llx %s\n", depth* 4, "    ",*address, *address + size, basename(reginfo.prp_vip.vip_path));
     
//        size = 0;
//        mach_vm_address_t addr = *address;
    }
    
    exit(0);
}
+ (void)load {

    
//        proc_pidinfo(pid, PROC_PIDLISTFDS, 0, procFDInfo, bufferSize);
//        int numberOfProcFDs = bufferSize / PROC_PIDLISTFD_SIZE;
    
//    pid_t pid = getpid();

//
//    struct proc_taskallinfo ff;
//    int sz = proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &ff, PROC_PIDTASKALLINFO_SIZE);
//
//
//    struct proc_workqueueinfo workqueue;
//    sz = proc_pidinfo(pid, PROC_PIDWORKQUEUEINFO, 0, &workqueue, PROC_PIDWORKQUEUEINFO_SIZE);
//
//    // Get all them threads
//    sz = proc_pidinfo(pid, PROC_PIDWORKQUEUEINFO, 0, &workqueue, PROC_PIDWORKQUEUEINFO_SIZE);
//
//    uint64_t threads;
//    sz = proc_pidinfo(pid, PROC_PIDLISTTHREADS, 0, &threads, PROC_PIDLISTTHREADS_SIZE);
//
//    struct proc_threadinfo thread_info;
//    sz = proc_pidinfo(pid, PROC_PIDTHREADINFO, 0, &thread_info, PROC_PIDTHREADINFO_SIZE);
//
//    char pidlistfd[0x400];
//    sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &pidlistfd, PROC_PIDLISTFD_SIZE);
//
//    uintptr_t unknown[5]; // private
//    sz = proc_pidinfo(pid, 0x14 /*0x20*/, 0, unknown, 0x28);
//
//
////    struct proc_threadinfo thread_info;
//    sz = proc_pidinfo(pid, PROC_PIDTHREADINFO, threads, &thread_info, PROC_PIDTHREADINFO_SIZE);
  
    ////////////////////////////////////////////////////////////////////////////////////
    
    
//    if (!pd) { perror("couldn't find pid\n"); exit(1); }
//    mach_vm_address_t address = 0;
//
//    task_t pid_task = 0;
//    kern_return_t kr = task_for_pid(mach_task_self(), pd, &pid_task);
//    if (kr != KERN_SUCCESS) {
//        perror("task_for_pid\n");
//        return;
//    }
//    getRegions(pid_task, &address);
    ///////////////////////////////////////////////////////////////////////////////
//    getNoRecurseRegions(pd, &address, 0);
//    printf("ok,");
    
//    sz = proc_pidinfo(0x2FE, PROC_PIDREGIONPATHINFO, 0, &regioninfo, PROC_PIDREGIONPATHINFO_SIZE);
    
//    // Figure out the size of the buffer needed to hold the list of open FDs
//    int bufferSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
//    if (bufferSize == -1) {
////        printf(UNABLE_TO_GET_PROC_FDS, pid);
////        return 1;
//        perror("proc_pidinfo");
//    }
//
//    // Get the list of open FDs
//    struct proc_fdinfo *procFDInfo = (struct proc_fdinfo *)malloc(bufferSize);
//    if (!procFDInfo) {
////        printf(OUT_OF_MEMORY, bufferSize);
////        return 1;
//        perror("malloc");
//    }
//    proc_pidinfo(pid, PROC_PIDLISTFDS, 0, procFDInfo, bufferSize);
//    int numberOfProcFDs = bufferSize / PROC_PIDLISTFD_SIZE;
//
//    int i;
//    for(i = 0; i < numberOfProcFDs; i++) {
//        if(procFDInfo[i].proc_fdtype == PROX_FDTYPE_VNODE) {
//            // A file is open
//            struct vnode_fdinfowithpath vnodeInfo;
//            int bytesUsed = proc_pidfdinfo(pid, procFDInfo[i].proc_fd, PROC_PIDFDVNODEPATHINFO, &vnodeInfo, PROC_PIDFDVNODEPATHINFO_SIZE);
//            if (bytesUsed == PROC_PIDFDVNODEPATHINFO_SIZE) {
//                printf(OPEN_FILE, vnodeInfo.pvip.vip_path);
//            }
//        } else if(procFDInfo[i].proc_fdtype == PROX_FDTYPE_SOCKET) {
//            // A socket is open
//            struct socket_fdinfo socketInfo;
//            int bytesUsed = proc_pidfdinfo(pid, procFDInfo[i].proc_fd, PROC_PIDFDSOCKETINFO, &socketInfo, PROC_PIDFDSOCKETINFO_SIZE);
//            if (bytesUsed == PROC_PIDFDSOCKETINFO_SIZE) {
//                if(socketInfo.psi.soi_family == AF_INET && socketInfo.psi.soi_kind == SOCKINFO_TCP) {
//                    int localPort = (int)ntohs(socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
//                    int remotePort = (int)ntohs(socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);
//                    if (remotePort == 0) {
//                        // Remote port will be 0 when the FD represents a listening socket
//                        printf(LISTENING_ON_PORT, localPort);
//                    } else {
//                        // Remote port will be non-0 when the FD represents communication with a remote socket
//                        printf(OPEN_SOCKET, localPort, remotePort);
//                    }
//                }
//            }
//        }
//    }

    

    //    for (int i = 0; i < num_pids; i++) {
    
    //        pid_t pid = pids[i];
    ////////////////////////////////////////////////////////////
//    struct proc_regionwithpathinfo info = {};
//    int k = proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, 0, &info, PROC_PIDREGIONPATHINFO_SIZE);
//    if (k < 0) {
//        printf("test\n");
//    }
//    long cur = info.prp_prinfo.pri_address + info.prp_prinfo.pri_size;
//    uintptr_t previous = 0;
//    char cur_prot[4] = {};
//    char max_prot[4] = {};
//
//
//    while (previous != info.prp_prinfo.pri_address) {
//        previous = info.prp_prinfo.pri_address;
//        get_rwx_string(info.prp_prinfo.pri_protection, cur_prot);
//        get_rwx_string(info.prp_prinfo.pri_max_protection, max_prot);
//        char *path = info.prp_vip.vip_path;
//        if (path[0] != '\00') {
//            //                if (strcmp(basename(path), libName) == 0) {
//            //                    proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, 0, &info, PROC_PIDREGIONPATHINFO_SIZE);
//            //                    printf("%s\n", info.prp_vip.vip_path);
//            //                    break;
//            //                }
//            printf("0x%011llx-0x%011llx %s/%s %s\n",
//                   info.prp_prinfo.pri_address,
//                   info.prp_prinfo.pri_address + info.prp_prinfo.pri_size,
//                   cur_prot,
//                   max_prot,
//                   info.prp_vip.vip_path);
//
//        }
//
//
//        __unused long a = proc_pidinfo(getpid(), PROC_PIDREGIONPATHINFO, cur, &info, PROC_PIDREGIONPATHINFO_SIZE);
//
//
//        cur = info.prp_prinfo.pri_address + info.prp_prinfo.pri_size + 1;
//
//
//    }
    
    
    
}

@end
