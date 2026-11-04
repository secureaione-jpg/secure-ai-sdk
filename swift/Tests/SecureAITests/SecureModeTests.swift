import CryptoKit
import Foundation
import Security
import XCTest
@testable import SecureAI

/// Secure mode end to end, with the enclave played by an RSA key we hold.
/// The verifier itself is tested against a real document in AttestationTests;
/// here the verified key is placed in the cache, as a successful check would.
final class SecureModeTests: XCTestCase {
    var privateKey: SecKey!
    var spki: Data!

    override func setUp() {
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
        privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, nil)!
        let pkcs1 = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(privateKey)!, nil)! as Data
        spki = Self.spki(pkcs1)
    }

    /// PKCS #1 wrapped as the SubjectPublicKeyInfo the enclave publishes.
    static func spki(_ pkcs1: Data) -> Data {
        func der(_ tag: UInt8, _ body: Data) -> Data {
            let n = body.count
            let len: Data = n < 128 ? Data([UInt8(n)]) : n < 256 ? Data([0x81, UInt8(n)]) : Data([0x82, UInt8(n >> 8), UInt8(n & 0xff)])
            return Data([tag]) + len + body
        }
        let alg = der(0x30, Data([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]))
        return der(0x30, alg + der(0x03, Data([0]) + pkcs1))
    }

    /// Opens what the client sealed, as the enclave would.
    func open(_ envelope: Data) throws -> (body: [String: Any], session: SymmetricKey) {
        let e = try JSONSerialization.jsonObject(with: envelope) as! [String: Any]
        let wrapped = Data(base64Encoded: e["k"] as! String)!
        let raw = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionOAEPSHA256, wrapped as CFData, nil)! as Data
        let session = SymmetricKey(data: raw)
        let box = try AES.GCM.SealedBox(combined: Data(base64Encoded: e["c"] as! String)!)
        let body = try JSONSerialization.jsonObject(with: try AES.GCM.open(box, using: session)) as! [String: Any]
        return (body, session)
    }

    func piece(_ session: SymmetricKey, _ i: Int, _ text: String, final: Bool) throws -> String {
        let sealed = try AES.GCM.seal(Data(text.utf8), using: session, authenticating: Envelope.aad(i, final))
        let json = try JSONSerialization.data(withJSONObject: ["i": i, "final": final, "c": sealed.combined!.base64EncodedString()])
        return "data: " + String(decoding: json, as: UTF8.self)
    }

    static let info = #"{"available":true,"enclave":"https://enclave.test","images":["aa"],"models":[{"id":"claude-sonnet-5-5","provider":"anthropic"},{"id":"gpt-6","provider":"openai"}],"default_model":"claude-sonnet-5-5","max_output_tokens":4096}"#

    /// A transport that answers discovery, and plays the relay and the enclave.
    final class Enclave: SecureAITransport, @unchecked Sendable {
        var answer: (SymmetricKey) throws -> [String] = { _ in [] }
        var opened: [String: Any]?
        var sentHeaders: [String: String] = [:]
        var sentBody = Data()
        let test: SecureModeTests
        init(_ t: SecureModeTests) { test = t }

        func send(_ r: URLRequest) async throws -> (Data, HTTPURLResponse) {
            (Data(SecureModeTests.info.utf8), HTTPURLResponse(url: r.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        }
        func lines(_ r: URLRequest) async throws -> (AsyncThrowingStream<String, Error>, HTTPURLResponse) {
            sentHeaders = r.allHTTPHeaderFields ?? [:]
            sentBody = r.httpBody ?? Data()
            let (body, session) = try test.open(sentBody)
            opened = body
            let out = try answer(session)
            return (AsyncThrowingStream { c in out.forEach { c.yield($0) }; c.finish() },
                    HTTPURLResponse(url: r.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        }
    }

    func client(_ t: Enclave) async -> SecureAI {
        let sai = SecureAI(apiKey: "sai_test", transport: t)
        await sai.secure.setKey(spki, until: Date().addingTimeInterval(3600))
        return sai
    }

    func testSealsTheConversationAndReadsTheSealedAnswer() async throws {
        let t = Enclave(self)
        t.answer = { s in [
            try self.piece(s, 0, #"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Dear "}}"#, final: false),
            try self.piece(s, 1, #"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Sara"}}"#, final: true),
        ] }
        let pieces = Box<[String]>()
        pieces.value = []
        let text = try await client(t).secureChat([.user("Write to Sara Whitfield")], system: "Be brief.") { pieces.value!.append($0) }
        XCTAssertEqual(text, "Dear Sara")
        XCTAssertEqual(pieces.value, ["Dear ", "Sara"])
        XCTAssertEqual(t.opened?["provider"] as? String, "anthropic")
        XCTAssertEqual(t.opened?["path"] as? String, "/v1/messages")
        XCTAssertEqual((t.opened?["body"] as? [String: Any])?["max_tokens"] as? Int, 4096)
        XCTAssertEqual(t.opened?["system"] as? String, "Be brief.")
        XCTAssertEqual(t.sentHeaders["X-Model"], "claude-sonnet-5-5")
        XCTAssertFalse(String(decoding: t.sentBody, as: UTF8.self).contains("Sara"), "nothing readable on the wire")
    }

    func testAsksOpenAIInItsOwnShape() async throws {
        let t = Enclave(self)
        t.answer = { s in [try self.piece(s, 0, "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\ndata: [DONE]", final: true)] }
        let text = try await client(t).secureChat([.user("x")], model: "gpt-6")
        XCTAssertEqual(text, "Hi")
        XCTAssertEqual(t.opened?["path"] as? String, "/v1/chat/completions")
        XCTAssertEqual((t.opened?["body"] as? [String: Any])?["max_completion_tokens"] as? Int, 4096)
    }

    func testRefusesAnAnswerCutShort() async throws {
        let t = Enclave(self)
        t.answer = { s in [try self.piece(s, 0, #"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Dear"}}"#, final: false)] }
        do { try await client(t).secureChat([.user("x")]); XCTFail("should throw") }
        catch let e as SecureModeError { XCTAssertTrue(e.message.contains("final")) }
    }

    func testRefusesPiecesOutOfOrder() async throws {
        let t = Enclave(self)
        t.answer = { s in [try self.piece(s, 1, "x", final: true)] }
        do { try await client(t).secureChat([.user("x")]); XCTFail("should throw") }
        catch let e as SecureModeError { XCTAssertTrue(e.message.contains("out of order")) }
    }

    func testRefusesAPieceSealedAsSomethingElse() async throws {
        let t = Enclave(self)
        // Sealed as "more", delivered claiming to be final: the binding fails.
        t.answer = { s in
            let sealed = try AES.GCM.seal(Data("x".utf8), using: s, authenticating: Envelope.aad(0, false))
            let json = try JSONSerialization.data(withJSONObject: ["i": 0, "final": true, "c": sealed.combined!.base64EncodedString()])
            return ["data: " + String(decoding: json, as: UTF8.self)]
        }
        do { try await client(t).secureChat([.user("x")]); XCTFail("should throw") }
        catch let e as SecureModeError { XCTAssertTrue(e.message.contains("did not open")) }
    }

    func testRefusesAModelTheEnclaveDoesNotOffer() async throws {
        let t = Enclave(self)
        do { try await client(t).secureChat([.user("x")], model: "secureai-auto"); XCTFail("should throw") }
        catch let e as SecureModeError { XCTAssertEqual(e.code, "model_not_available") }
        XCTAssertNil(t.opened, "nothing was sealed or sent")
    }

    func testReadsTheEnclaveKeyFromItsSPKI() {
        XCTAssertNotNil(Envelope.rsaKey(spki: spki))
        XCTAssertNil(Envelope.rsaKey(spki: Data([0x30, 0x01, 0x00])))
    }
}
