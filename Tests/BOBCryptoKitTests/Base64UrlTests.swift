//
//  Base64UrlTests.swift
//  
//
//  Created by Roland Persson on 2022-12-17.
//

import XCTest
@testable import BOBCryptoKit

final class Base64UrlTests: XCTestCase {

    func testEncodeDecodeEmpty() throws {
        let data = Data()
        try encodeDecode(data: data)
    }

    func testEncodeDecodeDifferentLengths() throws {
        let alphabet = "abcdefghijklmnopqrstuvwxyz"
        for length in 1..<16 {
            guard let data = alphabet.prefix(length).data(using: .utf8) else {
                XCTFail()
                return
            }
            try encodeDecode(data: data)
        }
    }

    func testEncodeDecodeRandomData() throws {
        for _ in 0..<10 {
            let size = Int.random(in: 5..<531)
            var data = Data(count: size)
            for x in 0..<size {
                data[x] = UInt8.random(in: 0...255)
            }

            try encodeDecode(data: data)
        }
    }

    private func encodeDecode(data: Data) throws {
        let encoded = data.base64UrlEncodedString()
        let decoded = try Data(base64UrlEncoded: encoded)
        XCTAssertEqual(data, decoded)
    }
}
