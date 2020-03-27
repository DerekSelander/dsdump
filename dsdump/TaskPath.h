//
//  TaskPath.hpp
//  xref
//
//  Created by Derek Selander on 5/7/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#ifndef TaskPath_hpp
#define TaskPath_hpp

#include <stdio.h>
#include <Foundation/Foundation.h>

//typedef enum _LibraryTaskError {
//    LibraryTaskErrorDyldVersion = 0,
//} LibraryTaskError;

//  BOOL FindLibraryInTask(pid_t task, char *search_string, LibraryTaskError* err) ;
void DumpProcessesContainingLibrary(const char *lib_name, uuid_t uuid);

#endif /* TaskPath_hpp */
