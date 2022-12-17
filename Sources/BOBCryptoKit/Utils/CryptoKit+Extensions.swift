//
//  Created by Roland Persson on 2022-11-02.
//

import Foundation
import CryptoKit

extension SharedSecret {
    /// This is the data representation of the shared secret. For EC
    /// keys this is the byte representation of a large integer found
    /// through the ECDH process.
    var sharedSecretData: Data {
        return withUnsafeBytes { bufferPointer in
            var data = Data()
            for b in bufferPointer {
                data.append(b)
            }
            return data
        }
    }
}
