//
//  YOYO.swift
//  xref
//
//  Created by Derek Selander on 5/17/19.
//  Copyright © 2019 Selander. All rights reserved.
//

import Cocoa

struct testStruct {
    let f = "some text"
}

class SubclassClass : YOYO {
    let z = "hi"
}


enum someEnum {
     case  aVal
    case  bVal
}


enum subclassedEnum : Error {
//    typealias RawValue = <#type#>
    
    case aVal
    case bVal
    case c
}

class YOYO: NSViewController {
    let someproperty = "https://www.google.com"
    let someotherproperty = "https://www.google.com"
    var avar = "https://www.google.com"
    func testyay() {
        print("yay")
    }
    
    class func someotherclassTest() {
        
        
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
