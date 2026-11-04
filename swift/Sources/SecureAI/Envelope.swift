import CryptoKit
import Foundation
import Security

/// The sealed envelope and the sealed stream, as lib/sealedEnvelope.ts in the
/// web repo writes and reads them (2026-10-08).
///
/// A fresh AES-256-GCM key per conversation, wrapped with RSA-OAEP-SHA-256 to
/// the key the enclave's attestation binds; the request encrypted under it.
/// The answer comes back in pieces, each bound to its position and to whether
/// it is the last, so a piece moved or a stream cut short fails to open
/// rather than opening as something else.
enum Envelope {
    static let version = 1

    struct Sealed: Encodable { let v: Int; let k: String; let c: String }

    struct Failure: Error, CustomStringConvertible { let description: String }

    /// Seal `body` to the enclave's attested SubjectPublicKeyInfo.
    static func seal(_ body: Data, to spki: Data) throws -> (envelope: Sealed, session: SymmetricKey) {
        guard let key = rsaKey(spki: spki) else { throw Failure(description: "the enclave's key could not be read") }
        let session = SymmetricKey(size: .bits256)
        let raw = session.withUnsafeBytes { Data($0) }
        var error: Unmanaged<CFError>?
        guard let wrapped = SecKeyCreateEncryptedData(key, .rsaEncryptionOAEPSHA256, raw as CFData, &error) as Data? else {
            throw Failure(description: "the session key could not be wrapped")
        }
        // combined is nonce ‖ ciphertext ‖ tag: what WebCrypto's iv ‖ encrypt() is.
        guard let combined = try AES.GCM.seal(body, using: session).combined else {
            throw Failure(description: "the request could not be sealed")
        }
        return (Sealed(v: version, k: wrapped.base64EncodedString(), c: combined.base64EncodedString()), session)
    }

    /// SecKey wants the PKCS #1 key inside a SubjectPublicKeyInfo.
    static func rsaKey(spki: Data) -> SecKey? {
        func element(_ b: [UInt8], _ at: Int) -> (tag: UInt8, start: Int, end: Int)? {
            guard at + 1 < b.count else { return nil }
            var i = at + 1
            var len = Int(b[i]); i += 1
            if len & 0x80 != 0 {
                let n = len & 0x7f
                guard n > 0, n <= 4, i + n <= b.count else { return nil }
                len = 0
                for _ in 0..<n { len = (len << 8) | Int(b[i]); i += 1 }
            }
            guard i + len <= b.count else { return nil }
            return (b[at], i, i + len)
        }
        let b = [UInt8](spki)
        guard let outer = element(b, 0), outer.tag == 0x30,
              let alg = element(b, outer.start), alg.tag == 0x30,
              let bits = element(b, alg.end), bits.tag == 0x03, bits.end > bits.start + 1 else { return nil }
        let pkcs1 = Data(b[(bits.start + 1)..<bits.end])
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        return SecKeyCreateWithData(pkcs1 as CFData, attrs as CFDictionary, nil)
    }

    static func aad(_ index: Int, _ final: Bool) -> Data {
        Data("secure-ai/v\(version)/\(index)/\(final ? "final" : "more")".utf8)
    }

    /// Reads a sealed stream in order, and refuses anything else.
    struct Reader {
        let session: SymmetricKey
        private var next = 0
        private(set) var complete = false

        init(session: SymmetricKey) { self.session = session }

        struct Piece: Decodable { let i: Int; let final: Bool; let c: String }

        mutating func open(_ piece: Piece) throws -> String {
            if complete { throw Failure(description: "stream already ended") }
            // Checked as well as bound into the encryption: the binding stops
            // a piece passing as another, this stops one replayed in place.
            guard piece.i == next else { throw Failure(description: "out of order: expected piece \(next), got \(piece.i)") }
            guard let blob = Data(base64Encoded: piece.c),
                  let box = try? AES.GCM.SealedBox(combined: blob),
                  let plain = try? AES.GCM.open(box, using: session, authenticating: aad(piece.i, piece.final)) else {
                throw Failure(description: "a piece of the answer did not open")
            }
            next += 1
            complete = piece.final
            return String(decoding: plain, as: UTF8.self)
        }

        /// Silence is not an ending: a stream that stopped without its final
        /// piece was cut short somewhere in the middle.
        func finish() throws {
            if !complete { throw Failure(description: "stream ended without a final piece") }
        }
    }
}
