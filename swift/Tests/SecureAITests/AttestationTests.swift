import Foundation
import XCTest
@testable import SecureAI

/// The real document enclave-v8 produced on 2026-09-04, signed by a Nitro
/// Security Module: the same fixture lib/attestation.test.ts checks, so the
/// two verifiers are held to the same answers.
final class AttestationTests: XCTestCase {
    static let nonce = "fixture-nonce-2026-09-04"
    static let pcr0 = "d1ad61b5cd042b645d172fedd6ea76b7bc70b84c8e60bafec57872f841b47eba13f2c448281856642ddc23c6f0936760"
    /// A minute after the document was produced.
    static let at = Date(timeIntervalSince1970: (1788542093431 + 60_000) / 1000)

    var document: String {
        let url = Bundle.module.url(forResource: "attestation-enclave-v8", withExtension: "json")!
        let json = try! JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        return json["document"] as! String
    }

    func check(nonce: String = nonce, trusted: [String] = [pcr0], now: Date = at, root: String = Attestation.nitroRootSHA256) -> Result<Attestation.Verified, Attestation.Failure> {
        Attestation.verify(documentBase64: document, nonce: nonce, trustedPCR0: trusted, rootFingerprint: root, now: now)
    }

    func reason(_ r: Result<Attestation.Verified, Attestation.Failure>) -> String {
        if case .failure(let f) = r { return f.description }
        return "verified"
    }

    func testAGenuineDocumentVerifiesAndYieldsTheKey() throws {
        let r = check()
        guard case .success(let v) = r else { return XCTFail(reason(r)) }
        XCTAssertEqual(v.pcr0, Self.pcr0)
        XCTAssertGreaterThan(v.publicKey.count, 200, "an RSA-2048 public key")
    }

    func testAnotherNonceIsAReplay() { XCTAssertTrue(reason(check(nonce: "some-other-nonce")).contains("nonce")) }
    func testAnUntrustedImageIsRefused() { XCTAssertTrue(reason(check(trusted: [String(repeating: "ab", count: 48)])).contains("PCR0")) }
    func testTrustingNothingTrustsNothing() { XCTAssertTrue(reason(check(trusted: [])).contains("PCR0")) }
    func testADayLateIsTooOld() { XCTAssertTrue(reason(check(now: Self.at.addingTimeInterval(86_400))).contains("old")) }
    func testAnotherRootIsRefused() { XCTAssertTrue(reason(check(root: String(repeating: "00", count: 32))).contains("root")) }

    func testATamperedDocumentDoesNotVerify() {
        var raw = Data(base64Encoded: document)!
        raw[raw.count - 10] ^= 0x01 // inside the signature
        let r = Attestation.verify(documentBase64: raw.base64EncodedString(), nonce: Self.nonce, trustedPCR0: [Self.pcr0], now: Self.at)
        XCTAssertTrue(reason(r).contains("signature"), reason(r))
    }

    func testTrailingBytesAreMalformed() {
        XCTAssertThrowsError(try CBOR.decode(Data([0x01, 0x02])))
    }
}
