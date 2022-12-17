//
//  Copyright (c) Bontouch AB 2022. All rights reserved.
//

import XCTest
@testable import BOBCryptoKit

final class ECIESwithSHA256DecrypterTests: XCTestCase {

    let testData = TestData()

    /// Test decrypting a 16 byte message which is the most common case.
    func testDecryptMessage1() throws {
        let encryptedData = try Data(base64UrlEncoded: testData.encryptedMessage_1)
        try verifyCorrectDecryptedResult(
            encryptedData: encryptedData,
            appPrivateKey: testData.appPrivateWebKey,
            expectedDecryptedResult: "abcdefghijklmnop".data(using: .utf8)!
        )
    }

    /// Test decrypting a longer message, different things happen compared to the case with
    /// 16 bytes. There are more iterations in the key derivation function for example
    /// (instead of just a single iteration)
    func testDecryptMessage2() throws {
        let encryptedData = try Data(base64UrlEncoded: testData.encryptedMessage_2)
        try verifyCorrectDecryptedResult(
            encryptedData: encryptedData,
            appPrivateKey: testData.appPrivateWebKey,
            expectedDecryptedResult: "abcdefghijklmnopqrstuvxyz".data(using: .utf8)!
        )
    }

    func testDecryptLargeBinaryMessage() throws {
        let plainTextBase64Url = """
            BxKW0bEhMZUwmVsylRWkBYXB9pgSUzuMMmf-Kxb8uCjPqsBAabuIAGSRdn7sZ0XYH7CcHdtBZZJJt9LMHQsgBzrvpFmhqf3oYCueHVG7SnCcqo4qL5WsfXShrbiRIyh59BHtOJgXcvYy7tfYUk60zdKd86MweAgA-6vCwbJLLVCe8lXQcgwPWvvYEwQAeKnIzH5OqCRM7vt6wtblgibtzE1ItK25g6ZdctHzQnG0qeVInZuA9cjsJmAMgN9ISGyQCZyEfNcVENdfYqI8PcEidTnG1TayrVqLcRMaBg-bgc9PE5DanDBCbiDKUjMCyv1_RjYNKgwB-8FFOqjgJ9O5kZAKcN--3yn7J1lEreGk9eJJXHry2uG4NseCIF2j84RosH_6JVQlgx55IGN-_h7IotJrNguV59xNtqTYktri3_eHTOE9W-IznzDw34oDWZTzor-DAt0SXskndA9U5w7s3WMxDisyT-sD-6VZjJ0z-KUwDNBk8k0wYAGYzJcpIicDhK-F_x0ECFeZy3H8_su-rCdi2jE7fbITf5CQ8sPHNCGfs9qrxZEGAWKF5ghaCDI25gCnbsMfnnGyDY_pHYBsWlwQfdm1qforvtCLHmo0YWT_-CpSt38am_2VbelhhZ0Q2MhsAd_W1DCrEr4p7K3uB7ie2Z3pctWbl3zADv-_usUkKxz5FsZ2JTv2JyQgoTbhjcx97lCrQ1YMKMC7KctgtcS6it6SHtjAE5v16EzV4NOs9Qg1hpdqDL2o8CtYCWgCMOvio2_qvXDuE8-ROokvKXcIQhJI09VWW5-108XI9MdWqiR6LY_Gqhg1NNC1X511BiF-g_onmi1wcwxf8Xe3GRa7pgExVsw49LIT0A9cnPaiC80pIR2IgdbZ5o8d6k4Dxd94dkOF4H53kLcxnu6HRUuXQ3jmGPDFPavfEdOr_uKr1PAFDwdhf6rdYJI7ERwNM7hNQZoQmrWqCkSWW2crEIUa7Bmko-qvK8Ys7MFzAwdBejJuLMnSj_LbqjBGWU-aA5GQrffIKYis
        """

        let encryptedDataBase64Url = """
        BDveF6dxrc249PAfQsKI9Z0UELxd0gFYJlBaBgb8wNSp7jUTtBlJhIHc7tVIkqrURQ1MM3ZvpfK211IJM_RCYc9xjy_JL4SPfJMUPNLMkmoGh8uGwTChIbAha8OFu-vIMzJO9DzJ3g7aPSTY6j7wixSKqDLCULXBwekUL5HvTLOEaNvfeVmTCVMLelTv2zSPUd12gR8MFrNU0k-upEzHALhj5DqsM5a5CnOBhDQvQSmHRMQle20yK0yqe1vc25UL9Jglmv4CMnrRb8PRfzwlUnMPeKCwGafIkkLUZArbAfXJGVHT19g_KbjALtY4QcOJIyQ17AgHNnkmfgtbDhDoFxTXOJl4ihLByHqtxbUttdr5Q4D-Fvyi39fEyBrW5G14QKdaffiQJ-ahun85RE9eNOGN85bw-jEEqPSTjqY58HfK8obyjRgDMTGYEBsYpS2kJU1dux3k7iOtpS8rz2glOQ3i5kw9uUHcOTU1MHqqUSUk8p-GhXUCSEnz6Lq-4vpb2B8IG9_J3cJ9O7MFqJkAT_BvNEm4sy4GrNBuAkoqOkMloilQRdQ3l3GYIs9NrXagRG89Mcvxj9BEFnwmZDwPQiSWOaCM2bdh9rT7ByBqUIZ906-bp7cO0rj7vhcS0fY9U_XY7RnQSbVHi2mYSY-z5GxueUX4usAYK1N4tWK7EkXUQA1lCraceFLyyqmKcwKv1WwBNoI9otZcUyEqQ4fIKL357CDJZipUwBBR6LBAxJ5-48ZpVvw07i5m2y-YymnWEBjqAbV4kcK3xmewBy3EB81eph6R59rqL5Evi6AqbDvHm0kp_WdkCke4EoRm-2GOqOKS4ConsJ9l8btEv3CZFdsPF9-Q7siiO444nNu5WMQfa4EzZvrQrKw_jo_65oR0GJDOefYcsiYFRjfyVgKWTY2ekaYjPcuY4Yi69WUO7xIpHLoSY2JKHO65Pn7ZVro7KcGZcIRjDUmcfmq4FMkUF8QOUVywz1mFVCHMEe72T14rYlC64kJo1S9VhMAzb3_uWzy7RFwnIGHXYUc3rGEziyn6ZY6Iapt95_Ya-AO6IH9X4F7W6XFRkPrIT7WDqmMpwdzxz90isgDCQ4Pt9XMkKSp2dJE7w_tEalGAossosIAjykSJ-8uESoPqWv1YELvM1pLVioRIYcJ2NA
        """

        let encryptedData = try Data(base64UrlEncoded: encryptedDataBase64Url)
        let expectedDecryptedResult = try Data(base64UrlEncoded: plainTextBase64Url)
        try verifyCorrectDecryptedResult(
            encryptedData: encryptedData,
            appPrivateKey: testData.appPrivateWebKey,
            expectedDecryptedResult: expectedDecryptedResult
        )
    }

    private func verifyCorrectDecryptedResult(
        encryptedData: Data,
        appPrivateKey: JWKPrivateKey,
        expectedDecryptedResult: Data
    ) throws {
        let privateKey = try appPrivateKey.privateKeyForKeyAgreement()
        let decrypter = try ECIESwithSHA256Decrypter(
            encryptedData: encryptedData,
            privateKey: privateKey
        )
        let plainText = try decrypter.decrypt()
        if plainText != expectedDecryptedResult {
            XCTFail(
                String(
                    format: "The decrypted data doesn't match the expected actual: %@ != expected: %@",
                    plainText.base64UrlEncodedString(),
                    expectedDecryptedResult.base64UrlEncodedString()
                )
            )
        }
    }
}
