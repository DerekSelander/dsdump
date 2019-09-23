//
//  TestSwift.swift
//  dsdump
//
//  Created by Derek Selander on 8/26/19.
//  Copyright © 2019 Selander. All rights reserved.
//

import Foundation


protocol AProtocol {
    func yay() 
}

struct someTest : AProtocol {
    var blah : String!
    var num : Int = 4
    
    func somefunc() {}
    func yay() {
        
    }
}
