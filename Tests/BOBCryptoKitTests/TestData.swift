//
//  Copyright (c) Bontouch AB 2022. All rights reserved.
//

import Foundation

class TestData {
    // A private key used to perform decryption. The encrypted data in tests have been
    // encrypted with the public key that belongs to the EC key pair.
    let appPrivateKey1_JSONData =  """
    {
      "kty": "EC",
      "kid": "Sales-312",
      "x": "ikFyJ4GC9j3pSLe4Lxxy9D78tO0UObhl7sMZmQ-kMtU",
      "y": "rD_WmtfZk5co4sQ0HsHzTUv7IyyEJSVqeJTGsOAXLV0",
      "crv": "P-256",
      "d": "S2_fFe03I1evWKQi7lw6Nh_LwrxKRj4x_99Ey8E0DLk"
    }
    """.data(using: .utf8)!

    let encryptedMessage_1 = "BEuXNbveL7WOOU6MjpTIM0s16RIiqIT5cZCQtlQ0R2ftkCd5ErfAb6zJ64GrTRYG6GHQOu5a6vFXbEr0kTrWYmfSbY61hYZtj8AuoaF0YNblWDZu4BVSzcFqeHynUN_jQEtBTd-8ffWpjSZ4ruRCfXc"

    let encryptedMessage_2 = "BJICl8j1X3PZdkquQHwouSQuIqJRJmSr8Lamct7wMneHTv9cpAtIzr9h2VChqM_HWjR_hBE401Om92OJ05ETNav53XVeukTAXJwAcIoCdfp_P0JUF1aCAK2Eapm7MCgjvUCSp8R8xTHbkTluJl3pluNlwuCwnf4wm2A"

    lazy var appPrivateWebKey = try! JSONDecoder().decode(
        JWKPrivateKey.self,
        from: appPrivateKey1_JSONData
    )
}

