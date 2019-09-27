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
    func hey()
}

struct someTest {
    var blah : String!
    var num : Int = 4
    
    func somefunc() {}
    func yay() {
        print("do stuff")
        
    }
    func hey() { }

}

extension someTest: AProtocol {

    func extensionTest() {
        print("\(#function)")
    }
}
