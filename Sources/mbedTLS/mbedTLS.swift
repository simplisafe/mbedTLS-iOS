//
//  mbedTLS.swift
//
//
//  Created by Siddarth Gandhi on 4/6/20.
//

import Foundation
import libmbedtls

public protocol mbedTLSDelegate {
    func handshakeCompleted()
}

public class mbedTLS {

    public static var delegate: mbedTLSDelegate?

    public static var sslContext: mbedtls_ssl_context!
    public static var sslConfig: mbedtls_ssl_config!
    public static var counterRandomByteGenerator: mbedtls_ctr_drbg_context!
    public static var entropy: mbedtls_entropy_context!
    public static var certChain1: CertificateChain!
    public static var certChain2: CertificateChain!
    public static var ecKeyPair: KeyPair!

    public static var readCallbackBuffer: [UInt8]?

    public typealias sslWriteCallback = (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int) ->  Int32
    public typealias sslReadCallback = (UnsafeMutableRawPointer?, UnsafeMutablePointer<UInt8>?, Int) ->  Int32
    public typealias KeyPair = mbedtls_pk_context
    public typealias CertificateChain = mbedtls_x509_crt

    static var sslWriteCallbackFunc: sslWriteCallback!
    static var sslReadCallbackFunc: sslReadCallback!

    public static var currentHandshakeState: HandshakeStep = .helloRequest

    static var ciphers: Array<Int32>!

    public init() throws {
        mbedTLS.sslContext = mbedtls_ssl_context()
        mbedTLS.sslConfig = mbedtls_ssl_config()
        mbedTLS.counterRandomByteGenerator = mbedtls_ctr_drbg_context()
        mbedTLS.entropy = mbedtls_entropy_context()
        mbedTLS.ecKeyPair = mbedtls_pk_context()

        mbedtls_ssl_init(&mbedTLS.sslContext)
        mbedtls_ssl_config_init(&mbedTLS.sslConfig)
        mbedtls_ctr_drbg_init(&mbedTLS.counterRandomByteGenerator)
        mbedtls_entropy_init(&mbedTLS.entropy)
        mbedtls_pk_init(&mbedTLS.ecKeyPair)

        let ret = mbedtls_ctr_drbg_seed(&mbedTLS.counterRandomByteGenerator, mbedtls_entropy_func, &mbedTLS.entropy, nil, 0)
        if ret != 0 { throw mbedTLSError.entropy }

        mbedTLS.initializeCertChain()
    }

    public static func initializeCertChain() {
        mbedTLS.certChain1 = CertificateChain()
        mbedTLS.certChain2 = CertificateChain()
        mbedtls_x509_crt_init(&mbedTLS.certChain1)
        mbedtls_x509_crt_init(&mbedTLS.certChain2)
    }

    public static func generateECKeyPair(ecpGroup: ECPGroup) throws -> KeyPair {
        mbedtls_pk_init(&mbedTLS.ecKeyPair)
        let privateKeySetup = mbedtls_pk_setup(&mbedTLS.ecKeyPair, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))
        if privateKeySetup != 0 { throw mbedTLSError.privateKeySetup }
        let keyPairGenerator = mbedtls_ecp_gen_key(mbedtls_ecp_group_id(rawValue: ecpGroup.rawValue), mbedtls_pk_ec(ecKeyPair), mbedtls_ctr_drbg_random, &counterRandomByteGenerator)
        if keyPairGenerator != 0 { throw mbedTLSError.keyPairGeneration }
        return ecKeyPair
    }

    public static func generateCSR(subject: String, keyPair: inout KeyPair) throws -> String {
        var csrContext = mbedtls_x509write_csr()
        mbedtls_x509write_csr_init(&csrContext)
        var signedSubjectBytes = subject.utf8.map { Int8(bitPattern: $0) }
        let setSubjectName = mbedtls_x509write_csr_set_subject_name(&csrContext, &signedSubjectBytes)
        if setSubjectName != 0 { throw mbedTLSError.parsingSubjectName }
        mbedtls_x509write_csr_set_key(&csrContext, &keyPair)
        mbedtls_x509write_csr_set_md_alg(&csrContext, MBEDTLS_MD_SHA256)
        var buffer = [UInt8](repeating: 0, count: 4096)
        let csrAsPemString = mbedtls_x509write_csr_pem(&csrContext, &buffer, 4096, mbedtls_ctr_drbg_random, &counterRandomByteGenerator)
        if csrAsPemString == 0 {
            let csrBytes = buffer.filter( { $0 != 0 } )
            guard let csrstring = String(bytes: csrBytes, encoding: .utf8) else { throw mbedTLSError.csrGeneration }
            return csrstring
        } else {
            throw mbedTLSError.csrGeneration
        }
    }

    public static func setupSSLContext() throws {
        let configureSSL = mbedtls_ssl_config_defaults(&sslConfig, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)
        if configureSSL != 0 { throw mbedTLSError.sslConfiguration }

        mbedtls_ssl_conf_rng(&sslConfig, mbedtls_ctr_drbg_random, &counterRandomByteGenerator)

        let setupSSL = mbedtls_ssl_setup(&sslContext, &sslConfig)
        if setupSSL != 0 { throw mbedTLSError.sslSetup }
    }

    public static func setIOFuncs(contextParameter: inout String, _ read: @escaping sslReadCallback, _ write: @escaping sslWriteCallback) {
        sslReadCallbackFunc = read
        sslWriteCallbackFunc = write

        mbedtls_ssl_set_bio(&sslContext, &contextParameter, { mbedTLS.sslWriteCallbackFunc($0, $1, $2) }, { mbedTLS.sslReadCallbackFunc($0, $1, $2) }, nil)
    }

    public static func configureCipherSuites(_ cipherSuites: [Int32]) {
        mbedTLS.ciphers = cipherSuites
        mbedtls_ssl_conf_ciphersuites(&sslConfig, &mbedTLS.ciphers)
    }

    public static func setMinimumProtocolVersion(_ version: SSLProtocolVersion) {
        mbedtls_ssl_conf_min_version(&sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, version.rawValue)
    }

    public static func setMaximumProtocolVersion(_ version: SSLProtocolVersion) {
        mbedtls_ssl_conf_max_version(&sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, version.rawValue)
    }

    public static func enableDebugMessages(level: DebugThresholdLevel) {
        mbedtls_debug_set_threshold(Int32(level.rawValue))
        mbedtls_ssl_conf_dbg(&sslConfig, debug_msg, stdout)
    }

    public static func executeNextHandshakeStep() throws {
        if mbedTLS.currentHandshakeState == .helloRequest {
            _ = try handshakeStep()
            _ = try handshakeStep()
        } else if mbedTLS.currentHandshakeState == .handshakeCompleted {
            delegate?.handshakeCompleted()
        } else {
            if try handshakeStep() {
                switch mbedTLS.currentHandshakeState {
                case HandshakeStep.clientCertificate...HandshakeStep.clientFinished, HandshakeStep.flushBuffers...HandshakeStep.handshakeCompleted:
                    try executeNextHandshakeStep()
                default:
                    break
                }
            }
        }
    }

    private static func handshakeStep() throws -> Bool {
        let ret = mbedtls_ssl_handshake_step(&sslContext)
        if ret == 0 {
            guard let currentHandshakeState = HandshakeStep(rawValue: mbedTLS.currentHandshakeState.rawValue + 1) else { return false }
            if let sslContextState = HandshakeStep(rawValue: Int(sslContext.state)), currentHandshakeState == sslContextState {
                mbedTLS.currentHandshakeState = currentHandshakeState
                return true
            } else {
                throw mbedTLSError.handshakeStep
            }
        } else {
            throw mbedTLSError.handshakeStep
        }
    }

    public static func parseDerCertificate(_ derCert: [UInt8], chain: inout mbedtls_x509_crt) throws {
        let ret = mbedtls_x509_crt_parse(&chain, derCert, derCert.count)
        if ret != 0 { throw mbedTLSError.parseCertificate }
    }

    public static func parsePemCertificates(_ concatenatedPemCerts: String, chain: inout mbedtls_x509_crt) throws {
        let certificates = Array(concatenatedPemCerts.utf8)
        let ret = mbedtls_x509_crt_parse(&chain, certificates, certificates.count)
        if ret != 0 { throw mbedTLSError.parseCertificate }
    }

    public static func configureClientCert(with privateKey: inout KeyPair) throws {
        let ret = mbedtls_ssl_conf_own_cert(&sslConfig, &certChain1, &privateKey)
        if ret != 0 { throw mbedTLSError.configureClientCertificate }
    }

    public static func configureRootCACert() {
        mbedtls_ssl_conf_ca_chain(&sslConfig, &certChain2, nil)
    }

    public static func getDERFromKeyPair(_ keyPair: inout KeyPair) throws -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: 1024)
        let ret = mbedtls_pk_write_key_der(&keyPair, &buffer, 1024)
        if ret >= 0 {
            let bufferStart = buffer.count - Int(ret)
            return Array<UInt8>(buffer[bufferStart...])
        } else {
            throw mbedTLSError.keyPairToDER
        }
    }

    public static func parseKeyPairFromDER(_ bytes: inout [UInt8]) throws -> Bool {
        mbedTLS.ecKeyPair = mbedtls_pk_context()
        mbedtls_pk_init(&mbedTLS.ecKeyPair)
        let ret = mbedtls_pk_parse_key(&mbedTLS.ecKeyPair, &bytes, bytes.count, nil, 0)
        if ret == 0 {
            return true
        } else {
            throw mbedTLSError.parseKeyPair
        }
    }

    public static func write(_ data: inout [UInt8], completion: (() -> Void)? = nil) throws {
        let ret = mbedtls_ssl_write(&sslContext, &data, data.count)
        if ret < 0 {
            throw mbedTLSError.write
        } else if data.count - Int(ret) != 0 {
            throw mbedTLSError.write
        } else {
            completion?()
        }
    }

    public static func read(_ data: [UInt8], completion: (([UInt8]) -> [UInt8]?)? = nil) throws -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: data.count)
        let ret = mbedtls_ssl_read(&sslContext, &buffer, data.count)
        if ret < 0 {
            throw mbedTLSError.read
        }
        return completion?(buffer)
    }

}
