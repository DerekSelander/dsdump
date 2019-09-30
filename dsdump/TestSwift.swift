//
//  TestSwift.swift
//  dsdump
//
//  Created by Derek Selander on 8/26/19.
//  Copyright © 2019 Selander. All rights reserved.
//

import Foundation

// swiftc /Users/lolgrep/code/dsdump/dsdump/TestSwift.swift -sdk `xcrun --show-sdk-path  -sdk iphoneos` -target arm64e-apple-ios99.99.99.99 -o /tmp/TestSwift
protocol AProtocol {
    func yay()
    func hey()
}

enum WootYeah {
    case some
    case test
}

@_cdecl("do_stuff")
public func meh() {
    let a = SomeTest()
    print("\(a)")
 
}

struct SomeTest {
//    var blah : String!
    var numa : Int = 0
    var numb : Int = 2
    var numc : Int = 4
    
    func somefunc() {}
    func yay() {
        print("do stuff")
        
    }
    func hey() { }

}

extension SomeTest: AProtocol {

    func extensionTest() {
        print("\(#function)")
    }
}
