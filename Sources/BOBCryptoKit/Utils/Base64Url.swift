//
//  Copyright (c) Bontouch AB 2022. All rights reserved.
//

import Foundation

extension Data {
    init(base64UrlEncoded: String) throws {
        var base64Encoded = base64UrlEncoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64Encoded.count % 4 != 0 {
            base64Encoded = base64Encoded.appending("=")
        }
        guard let decoded = Data(base64Encoded: base64Encoded, options: .ignoreUnknownCharacters) else {
            throw Base64UrlConversionError.invalidData
        }

        self = decoded
    }

    func base64UrlEncodedString() -> String {
        let result = self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        return result
    }
}

enum Base64UrlConversionError: Error {
    case invalidData
}
