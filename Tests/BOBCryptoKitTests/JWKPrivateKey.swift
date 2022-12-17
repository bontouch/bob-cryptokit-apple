//
//  Copyright (c) Bontouch AB 2022. All rights reserved.
//

import Foundation
import CryptoKit

@testable import BOBCryptoKit

struct JWKPrivateKey: Codable {
    let kty: String
    let kid: String
    let x: String
    let y: String
    let crv: String
    let d: String
}

extension JWKPrivateKey {

    func privateKeyForKeyAgreement() throws -> P256.KeyAgreement.PrivateKey {
        let xBytes = try Data(base64UrlEncoded: x)
        let yBytes = try Data(base64UrlEncoded: y)
        let dBytes = try Data(base64UrlEncoded: self.d)

        var x963Data = Data()
        x963Data.append(0x04)
        x963Data.append(xBytes)
        x963Data.append(yBytes)
        x963Data.append(dBytes)

        return try P256.KeyAgreement.PrivateKey(x963Representation: x963Data)
    }
}
