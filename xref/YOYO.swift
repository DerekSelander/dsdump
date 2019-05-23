//
//  YOYO.swift
//  xref
//
//  Created by Derek Selander on 5/17/19.
//  Copyright © 2019 Selander. All rights reserved.
//

import Cocoa

class YOYO: NSViewController {
    let someproperty : NSString? = nil 
    func testyay() {
        print("yay")
    }
    private func someothertest() {
        print("woot")
    }
    
    @objc func someobjcmessage(num : Int, str : String) {
    
        YOYO.classTest()
    }
    
    static func >(left: YOYO, right: YOYO) -> Bool {
        return true
        
    }
    
    static func staticTest() {
    
        let a = YOYO()
        let b = YOYO()
        if (a > b) { }
    }
    
    class func classTest() {
        
    }
}
