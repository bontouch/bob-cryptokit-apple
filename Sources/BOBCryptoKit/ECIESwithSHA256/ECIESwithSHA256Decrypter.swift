//
//  Copyright (c) Bontouch AB 2022. All rights reserved.
//

import Foundation
import CryptoKit

///
/// Class capable of decrypting ECIES with SHA256.
///
/// Intended to decrypt keys in the BoB ticket standard that have been encrypted
/// with the private key of a device.
///
/// This class performs the reverse of the following encryption done in
/// java using the BouncyCastle crypto provider.
///
/// ```
/// Cipher encryptCipher = Cipher.getInstance(ECIES_WITH_SHA256, BouncyCastleProvider.PROVIDER_NAME);
/// encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
/// return encryptCipher.doFinal(deviceKeyK);
/// ```
///

public struct ECIESwithSHA256Decrypter {

    let kMACSizeBytes = 32
    let kMACKeySizeBits = 128

    let kEncodedPublicKeySizeBytes = 65 // 0x04 followed by 32 bytes each for the x, y pair.
    let encryptedData: Data
    let privateKey: P256.KeyAgreement.PrivateKey

    /// Initializes a decrypter with encrypted data and key.
    /// - Parameters:
    ///   - encryptedData: The encrypted data
    ///   - privateKey: The private EC key of the receiver of the encrypted message.
    ///
    ///  The encryted data is a sequence of bytes:
    ///     - the public key used in encryption i X9.63 uncompressed format.
    ///     - the encrypted message
    ///     - A hash HMAC128_SHA256 is used to verify a correct decryption.
    ///
    public init(encryptedData: Data, privateKey: P256.KeyAgreement.PrivateKey) throws {
        self.encryptedData = encryptedData
        self.privateKey = privateKey
    }

    /// Decrypts the encrypted data
    /// - Throws: ECIESwithSHA256Error or lower level errors.
    /// - Returns: the decrypted message
    public func decrypt() throws -> Data {
        // split encrypted data into publicKey, encrypted message and MAC
        let unpackedEncryptedData = try getUnpackedEncryptedData()

        // extract public key from data
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: unpackedEncryptedData.publicKeyData)

        // establish the shared secret
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let sharedSecretData = sharedSecret.sharedSecretData

        // calculate key data from shared secret
        let K1Size = encryptedData.count - kEncodedPublicKeySizeBytes - kMACSizeBytes
        let K2Size = kMACKeySizeBits / 8
        let keyLength = K1Size + K2Size

        var keyDerivationData = unpackedEncryptedData.publicKeyData
        keyDerivationData.append(sharedSecretData)
        let K = try ECIESwithSHA256_KDF(sharedSecret: keyDerivationData)
            .generateBytes(len: keyLength)

        let K2 = [UInt8](K[0..<K2Size])
        let K1 = [UInt8](K[K2Size..<K2Size + K1Size])

        // decrypt message with key data
        var M = [UInt8](unpackedEncryptedData.encryptedMessage)
        for i in 0..<M.count {
            M[i] = M[i] ^ K1[i]
        }

        let decryptedMessage = Data(M)

        // calculate MAC and verify by comparing to the extracted one
        let symmetricKey = SymmetricKey(data: K2)
        assert(symmetricKey.bitCount == 128)
        var mac = HMAC<SHA256>(key: symmetricKey)
        mac.update(data: unpackedEncryptedData.encryptedMessage)
        let L2 = [UInt8](repeating: 0, count: 8)
        mac.update(data: L2)
        let result = mac.finalize()

        if Data(result) != unpackedEncryptedData.mac {
            throw ECIESwithSHA256Error.macDoesntMatch
        }

        return decryptedMessage
    }

    struct UnpackedEncryptedData {
        let publicKeyData: Data
        let encryptedMessage: Data
        let mac: Data
    }

    private func getUnpackedEncryptedData() throws -> UnpackedEncryptedData {
        if encryptedData.count < kEncodedPublicKeySizeBytes + kMACSizeBytes {
            throw ECIESwithSHA256Error.invalidEncryptedData
        }

        let publicKeyData = encryptedData[0..<kEncodedPublicKeySizeBytes]
        let encryptedMessage = encryptedData[kEncodedPublicKeySizeBytes..<encryptedData.count - kMACSizeBytes]
        let mac = encryptedData[encryptedData.count - kMACSizeBytes..<encryptedData.count]

        assert(mac.count == kMACSizeBytes)

        return UnpackedEncryptedData(
            publicKeyData: publicKeyData,
            encryptedMessage: encryptedMessage,
            mac: mac
        )
    }
}

enum ECIESwithSHA256Error: Error {
    /// Something is wrong with the encrypted data.
    case invalidEncryptedData
    /// After decryption the HMAC doesn't match the expected value.
    case macDoesntMatch
}
