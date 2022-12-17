//
//  Copyright (c) Bontouch AB 2022. All rights reserved.
//

import Foundation
import CryptoKit

/// Key derivation function, ANSI X9.63 with SHA256
struct ECIESwithSHA256_KDF {

    let kSHA256DigestSize = 32 // SHA256 digest size in bytes

    let sharedSecret: Data
    var counterStart: Int32 = 1

    func generateBytes(len: Int) throws -> Data {
        var result = Data()

        let digestSize = kSHA256DigestSize
        var remaining = len

        let cThreshold = Int32((len + digestSize - 1) / digestSize)

        var C = counterStart.bigEndian.toByteArray()

        var counterBase = counterStart & ~0xFF

        for _ in 0..<cThreshold {

            var digest = CryptoKit.SHA256()
            digest.update(data: sharedSecret)
            digest.update(data: C)

            let dig = Data(digest.finalize())

            if remaining > digestSize {
                result.append(dig)
                remaining -= digestSize
            } else {
                result.append(dig[0..<remaining])
            }

            C[3] += 1
            if C[3] == 0 {
                counterBase += 0x100
                C = counterBase.bigEndian.toByteArray()
            }
        }

        return result
    }
}

private extension Int32 {
    func toByteArray() -> [UInt8] {
        return withUnsafeBytes(of: self) { pointer in
            var result = [UInt8]()
            for value in pointer {
                result.append(value)
            }
            return result
        }
    }
}
