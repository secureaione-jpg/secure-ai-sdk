import CryptoKit
import Foundation
import Security

/// Checking that the enclave is the program it says it is (2026-10-08).
///
/// The Swift half of lib/attestation.ts in the web repo, which the apps and
/// the TypeScript SDK use; the same checks in the same order. An AWS Nitro
/// enclave answers with a document signed by AWS's hardware: which program
/// is running (PCR0), the nonce this client sent, and the public key a
/// conversation should be sealed to. Every check below has to pass before
/// that key is believed. A failure is a reason, never a fallback.
enum Attestation {
    /// SHA-256 of the AWS Nitro Enclaves root certificate, pinned. Never taken
    /// from the document: a chain that vouches for its own root is a circle.
    static let nitroRootSHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"

    struct Verified {
        let publicKey: Data
        let pcr0: String
        /// Milliseconds since 1970.
        let timestamp: Double
    }

    enum Failure: Error, CustomStringConvertible {
        case reason(String)
        var description: String { if case .reason(let r) = self { return r }; return "" }
    }

    static func verify(
        documentBase64: String,
        nonce: String,
        trustedPCR0: [String],
        rootFingerprint: String = nitroRootSHA256,
        now: Date = Date(),
        maxAge: TimeInterval = 3 * 60 * 60
    ) -> Result<Verified, Failure> {
        func no(_ r: String) -> Result<Verified, Failure> { .failure(.reason(r)) }

        guard let raw = Data(base64Encoded: documentBase64) else { return no("malformed: not base64") }
        let cose: [CBOR]
        let doc: [CBOR: CBOR]
        do {
            guard case .array(let a) = try CBOR.decode(raw), a.count == 4 else { return no("not a COSE_Sign1") }
            cose = a
            guard case .bytes(let payload) = cose[2], case .map(let m) = try CBOR.decode(payload) else { return no("document is not a map") }
            doc = m
        } catch {
            return no("malformed: \(error)")
        }
        guard case .bytes(let protectedBytes) = cose[0], case .bytes(let payload) = cose[2], case .bytes(let signature) = cose[3] else {
            return no("not a COSE_Sign1")
        }

        // ES384 and nothing else. An algorithm the verifier honours is an
        // algorithm an attacker can choose.
        guard case .map(let header)? = try? CBOR.decode(protectedBytes), header[.int(1)] == .int(-35) else {
            return no("signature algorithm is not ES384")
        }

        guard case .bytes(let leafDER)? = doc[.text("certificate")],
              case .array(let bundle)? = doc[.text("cabundle")], !bundle.isEmpty else {
            return no("no certificate chain")
        }
        let cabundle: [Data] = bundle.compactMap { if case .bytes(let b) = $0 { return b }; return nil }
        guard cabundle.count == bundle.count else { return no("no certificate chain") }

        // The nonce, before anything expensive.
        guard case .bytes(let docNonce)? = doc[.text("nonce")], docNonce == Data(nonce.utf8) else {
            return no("nonce does not match — replayed or not ours")
        }

        guard case .int(let ts)? = doc[.text("timestamp")] else { return no("no timestamp") }
        let ageSeconds = abs(now.timeIntervalSince1970 * 1000 - Double(ts)) / 1000
        if ageSeconds > maxAge { return no("document is \(Int(ageSeconds / 60)) minutes old") }

        // The root, pinned.
        let rootFp = SHA256.hash(data: cabundle[0]).map { String(format: "%02x", $0) }.joined()
        guard rootFp == rootFingerprint.lowercased() else { return no("root is not the pinned AWS root (\(rootFp))") }

        // The chain, by the platform's own X.509 verifier, with the pinned
        // root as the only anchor and the clock this check is asked about.
        let certs = ([leafDER] + cabundle.dropFirst().reversed()).compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard certs.count == cabundle.count, let root = SecCertificateCreateWithData(nil, cabundle[0] as CFData) else {
            return no("a certificate could not be read")
        }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certs as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess, let trust else {
            return no("the chain could not be checked")
        }
        SecTrustSetAnchorCertificates(trust, [root] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        SecTrustSetNetworkFetchAllowed(trust, false)
        SecTrustSetVerifyDate(trust, now as CFDate)
        var trustError: CFError?
        guard SecTrustEvaluateWithError(trust, &trustError) else {
            return no("certificate chain does not verify: \(trustError.map { CFErrorCopyDescription($0) as String } ?? "unknown")")
        }

        // The document itself, under the leaf's key. COSE signs a
        // Sig_structure, not the payload.
        var sig = Data()
        sig.append(CBOR.encodeHead(major: 4, 4))
        sig.append(CBOR.encodeText("Signature1"))
        sig.append(CBOR.encodeBytes(protectedBytes))
        sig.append(CBOR.encodeBytes(Data()))
        sig.append(CBOR.encodeBytes(payload))
        guard let leafKey = SecCertificateCopyKey(certs[0]), let derSig = derSignature(rawP384: signature) else {
            return no("document signature could not be checked")
        }
        guard SecKeyVerifySignature(leafKey, .ecdsaSignatureMessageX962SHA384, sig as CFData, derSig as CFData, nil) else {
            return no("document signature does not verify")
        }

        // What it says: which program, and the key.
        guard case .map(let pcrs)? = doc[.text("pcrs")], case .bytes(let pcr0Bytes)? = pcrs[.int(0)] else {
            return no("no PCR0 in the document")
        }
        let pcr0 = pcr0Bytes.map { String(format: "%02x", $0) }.joined()
        guard trustedPCR0.map({ $0.lowercased() }).contains(pcr0) else {
            return no("PCR0 \(pcr0) is not one this client trusts")
        }
        guard case .bytes(let publicKey)? = doc[.text("public_key")], !publicKey.isEmpty else {
            return no("the document binds no public key")
        }
        return .success(Verified(publicKey: publicKey, pcr0: pcr0, timestamp: Double(ts)))
    }

    /// COSE carries ECDSA as raw r‖s; the platform wants DER.
    static func derSignature(rawP384 raw: Data) -> Data? {
        guard raw.count == 96 else { return nil }
        func integer(_ bytes: Data) -> Data {
            var b = Data(bytes.drop(while: { $0 == 0 }))
            if b.isEmpty { b = Data([0]) }
            if b[b.startIndex] & 0x80 != 0 { b.insert(0, at: b.startIndex) }
            return Data([0x02, UInt8(b.count)]) + b
        }
        let body = integer(raw.prefix(48)) + integer(raw.suffix(48))
        return Data([0x30, UInt8(body.count)]) + body
    }
}

/// Just enough CBOR for an attestation document, and strict: trailing bytes
/// after a value are how two parsers come to disagree about what was signed.
indirect enum CBOR: Hashable {
    case int(Int64)
    case bytes(Data)
    case text(String)
    case array([CBOR])
    case map([CBOR: CBOR])
    case bool(Bool)
    case null

    struct Malformed: Error {}

    var byteValue: Data? { if case .bytes(let b) = self { return b }; return nil }
    var textValue: String? { if case .text(let t) = self { return t }; return nil }

    static func decode(_ data: Data) throws -> CBOR {
        var r = Reader(bytes: [UInt8](data))
        let v = try r.value()
        guard r.pos == r.bytes.count else { throw Malformed() }
        return v
    }

    private struct Reader {
        let bytes: [UInt8]
        var pos = 0

        mutating func byte() throws -> UInt8 {
            guard pos < bytes.count else { throw Malformed() }
            defer { pos += 1 }
            return bytes[pos]
        }

        mutating func length(_ info: UInt8) throws -> UInt64 {
            switch info {
            case 0..<24: return UInt64(info)
            case 24: return UInt64(try byte())
            case 25, 26, 27:
                let n = info == 25 ? 2 : info == 26 ? 4 : 8
                var v: UInt64 = 0
                for _ in 0..<n { v = (v << 8) | UInt64(try byte()) }
                return v
            default: throw Malformed()
            }
        }

        mutating func take(_ n: UInt64) throws -> [UInt8] {
            guard n <= UInt64(bytes.count - pos) else { throw Malformed() }
            defer { pos += Int(n) }
            return Array(bytes[pos..<pos + Int(n)])
        }

        /// True while an indefinite item continues; consumes the break.
        mutating func peekIsNotBreak() throws -> Bool {
            guard pos < bytes.count else { throw Malformed() }
            if bytes[pos] == 0xff { pos += 1; return false }
            return true
        }

        mutating func value() throws -> CBOR {
            let first = try byte()
            let major = first >> 5, info = first & 0x1f
            switch major {
            case 0:
                let v = try length(info)
                guard v <= UInt64(Int64.max) else { throw Malformed() }
                return .int(Int64(v))
            case 1:
                let v = try length(info)
                guard v < UInt64(Int64.max) else { throw Malformed() }
                return .int(-1 - Int64(v))
            // Indefinite lengths (info 31) run to a 0xff break. The Nitro
            // module writes its document map that way.
            case 2, 3:
                var raw: [UInt8] = []
                if info == 31 {
                    while try peekIsNotBreak() {
                        guard case let chunk = try value(), let part = (major == 2 ? chunk.byteValue : chunk.textValue.map { Data($0.utf8) }) else { throw Malformed() }
                        raw += part
                    }
                } else {
                    raw = try take(try length(info))
                }
                if major == 2 { return .bytes(Data(raw)) }
                guard let s = String(bytes: raw, encoding: .utf8) else { throw Malformed() }
                return .text(s)
            case 4:
                if info == 31 {
                    var items: [CBOR] = []
                    while try peekIsNotBreak() { items.append(try value()) }
                    return .array(items)
                }
                let n = try length(info)
                guard n <= UInt64(bytes.count) else { throw Malformed() }
                return .array(try (0..<n).map { _ in try value() })
            case 5:
                var m: [CBOR: CBOR] = [:]
                if info == 31 {
                    while try peekIsNotBreak() { let k = try value(); m[k] = try value() }
                    return .map(m)
                }
                let n = try length(info)
                guard n <= UInt64(bytes.count) else { throw Malformed() }
                for _ in 0..<n { let k = try value(); m[k] = try value() }
                return .map(m)
            case 6:
                _ = try length(info) // a tag: the value under it is what matters
                return try value()
            case 7:
                switch info {
                case 20: return .bool(false)
                case 21: return .bool(true)
                case 22, 23: return .null
                default: throw Malformed()
                }
            default: throw Malformed()
            }
        }
    }

    static func encodeHead(major: UInt8, _ n: Int) -> Data {
        switch n {
        case 0..<24: return Data([(major << 5) | UInt8(n)])
        case 24..<0x100: return Data([(major << 5) | 24, UInt8(n)])
        case 0x100..<0x10000: return Data([(major << 5) | 25, UInt8(n >> 8), UInt8(n & 0xff)])
        default: return Data([(major << 5) | 26, UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff), UInt8((n >> 8) & 0xff), UInt8(n & 0xff)])
        }
    }
    static func encodeBytes(_ b: Data) -> Data { encodeHead(major: 2, b.count) + b }
    static func encodeText(_ s: String) -> Data { let b = Data(s.utf8); return encodeHead(major: 3, b.count) + b }
}
