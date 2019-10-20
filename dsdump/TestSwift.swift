//
//  TestSwift.swift
//  dsdump
//
//  Created by Derek Selander on 8/26/19.
//  Copyright © 2019 Selander. All rights reserved.
//

import Foundation
import Cocoa
// swiftc /Users/lolgrep/code/dsdump/dsdump/TestSwift.swift -sdk `xcrun --show-sdk-path  -sdk iphoneos` -target arm64e-apple-ios99.99.99.99 -o /tmp/TestSwift
protocol AProtocol {
    func yay()
//    func hey()
}

enum FFF {
    case yo
}

public class SomeVC : NSViewController, AProtocol {
    public var someview : NSView!
    let h : SomeVC? = nil
    let jj : Int32 = 3
    var someStr : NSString = "yay some string"
    override public func viewDidLoad() {
        super.viewDidLoad()
        self.someview = NSView()
        
    }
    
    override init(nibName nibNameOrNil: NSNib.Name?, bundle nibBundleOrNil: Bundle?) {
        super.init(nibName: nibNameOrNil, bundle: nibBundleOrNil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    public func yay() {
        
    }
}
 

/*
private class PrivateClass {
    
}

public enum WootYeah {
    case some
    case test
}

@_cdecl("do_stuff")
public func meh() {
    let a = SomeTest()
    print("\(a)")
 
}

public class SomeTest {
//    var blah : String!
    var numa : Int = 0
    var numb : Int = 2
    var numc : Int = 4
    
    func somefunc() {}
    public func yay() {
        print("do stuff")
        
    }
    func hey() { }

}

extension SomeTest: AProtocol {

    func extensionTest() {
        print("\(#function)")
    }
}
*/
