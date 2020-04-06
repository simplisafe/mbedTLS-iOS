//
//  ECPGroup.swift
//  
//
//  Created by Siddarth Gandhi on 4/6/20.
//

import Foundation

public enum ECPGroup: UInt32 {
    case none = 0, secp192r1, secp224r1, secp256r1, secp384r1, secp521r1
    case bp256r1, bp384r1, bp512r1, curve25519
    case secp192k1, secp224k1, secp256k1, curve448
}
