//
//  mbedTLS.swift
//  mbedTLS
//
//  Created by Siddarth Gandhi on 2/21/19.
//  Copyright © 2019 SimpliSafe. All rights reserved.
//

import Foundation
import libmbedtls

public protocol mbedTLSDelegate {
    func handshakeCompleted()
}

public class mbedTLS {
    
    public static var delegate: mbedTLSDelegate?
    
    public enum HandshakeSteps: Int, Strideable {
        case helloRequest = 0, clientHello
        case serverHello, serverCertificate, serverKeyExchange, serverCertificateRequest, serverHelloDone
        case clientCertificate, clientKeyExchange, certificateVerify, clientChangeCipherSpec, clientFinished
        case serverChangeCipherSpec, serverFinished, flushBuffers, handshakeWrapup, handshakeCompleted
        
        public typealias Stride = Int
        
        public func distance(to other: mbedTLS.HandshakeSteps) -> Int {
            return Stride(other.rawValue) - Stride(self.rawValue)
        }
        
        public func advanced(by n: Int) -> mbedTLS.HandshakeSteps {
            return mbedTLS.HandshakeSteps(rawValue: self.rawValue + n)!
        }
    }
    
    public enum SSLProtocolVersion: Int32 {
        case sslProtocol10 = 1
        case sslProtocol11 = 2
        case sslProtocol12 = 3
    }
    
    public enum ECPGroup: UInt32 {
        case none = 0, secp192r1, secp224r1, secp256r1, secp384r1, secp521r1
        case bp256r1, bp384r1, bp512r1, curve25519
        case secp192k1, secp224k1, secp256k1, curve448
    }
    
    public enum DebugThresholdLevel: Int {
        case noDebug = 0, error, stateChange, informational, verbose
    }
    
    public static var sslContext: mbedtls_ssl_context!
    public static var sslConfig: mbedtls_ssl_config!
    public static var counterRandomByteGenerator: mbedtls_ctr_drbg_context!
    public static var entropy: mbedtls_entropy_context!
    public static var certChain1: mbedtls_x509_crt!
    public static var certChain2: mbedtls_x509_crt!
    public static var ecKeyPair: mbedtls_pk_context!
    
    public static var readCallbackBuffer: [UInt8]?
    
    public typealias sslWriteCallback = (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int) ->  Int32
    public typealias sslReadCallback = (UnsafeMutableRawPointer?, UnsafeMutablePointer<UInt8>?, Int) ->  Int32
    public typealias KeyPair = mbedtls_pk_context
    
    static var sslWriteCallbackFunc: sslWriteCallback!
    static var sslReadCallbackFunc: sslReadCallback!
    
    public static var currentHandshakeState: HandshakeSteps = .helloRequest
    
    static var ciphers: Array<Int32>!
    
    public init() {
        mbedTLS.sslContext = mbedtls_ssl_context()
        mbedTLS.sslConfig = mbedtls_ssl_config()
        mbedTLS.counterRandomByteGenerator = mbedtls_ctr_drbg_context()
        mbedTLS.entropy = mbedtls_entropy_context()
        mbedTLS.certChain1 = mbedtls_x509_crt()
        mbedTLS.certChain2 = mbedtls_x509_crt()
        mbedTLS.ecKeyPair = mbedtls_pk_context()
        
        mbedtls_ssl_init(&mbedTLS.sslContext)
        mbedtls_ssl_config_init(&mbedTLS.sslConfig)
        mbedtls_ctr_drbg_init(&mbedTLS.counterRandomByteGenerator)
        mbedtls_entropy_init(&mbedTLS.entropy)
        mbedtls_x509_crt_init(&mbedTLS.certChain1)
        mbedtls_x509_crt_init(&mbedTLS.certChain2)
        mbedtls_pk_init(&mbedTLS.ecKeyPair)
        
        if mbedtls_ctr_drbg_seed(&mbedTLS.counterRandomByteGenerator, mbedtls_entropy_func, &mbedTLS.entropy, nil, 0) != 0 {
            print("mbedtls_ctr_drbg_seed failed!")
            return
        }
    }
    
    public static func generateECKeyPair(ecpGroup: ECPGroup) -> KeyPair {
        mbedtls_pk_init(&mbedTLS.ecKeyPair)
        mbedtls_pk_setup(&mbedTLS.ecKeyPair, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))
        mbedtls_ecp_gen_key(mbedtls_ecp_group_id(rawValue: ecpGroup.rawValue), mbedtls_pk_ec(ecKeyPair), mbedtls_ctr_drbg_random, &counterRandomByteGenerator)
        return ecKeyPair
    }
    
    public static func generateCSR(subject: String, keyPair: inout KeyPair) -> String? {
        var csrContext = mbedtls_x509write_csr()
        mbedtls_x509write_csr_init(&csrContext)
        var signedSubjectBytes = subject.utf8.map { Int8(bitPattern: $0) }
        mbedtls_x509write_csr_set_subject_name(&csrContext, &signedSubjectBytes)
        mbedtls_x509write_csr_set_key(&csrContext, &keyPair)
        mbedtls_x509write_csr_set_md_alg(&csrContext, MBEDTLS_MD_SHA256)
        var buffer = [UInt8](repeating: 0, count: 4096)
        if mbedtls_x509write_csr_pem(&csrContext, &buffer, 4096, mbedtls_ctr_drbg_random, &counterRandomByteGenerator) == 0 {
            let csrBytes = buffer.filter( { $0 != 0 } )
            let csrstring = String(bytes: csrBytes, encoding: .utf8)
            return csrstring
        } else {
            return nil
        }
    }
    
    public static func setupSSLContext() {
        if mbedtls_ssl_config_defaults(&sslConfig, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0 {
            print("mbedtls_ssl_config_defaults failed!")
            return
        }
        
        mbedtls_ssl_conf_rng(&sslConfig, mbedtls_ctr_drbg_random, &counterRandomByteGenerator)

        if mbedtls_ssl_setup(&sslContext, &sslConfig) != 0 {
            print("mbedtls_ssl_setup failed!")
            return
        }
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
    
    public static func executeNextHandshakeStep() {
        if mbedTLS.currentHandshakeState == .helloRequest {
            mbedtls_ssl_handshake_client_step(&sslContext)
            mbedtls_ssl_handshake_client_step(&sslContext)
            mbedTLS.currentHandshakeState = HandshakeSteps(rawValue: mbedTLS.currentHandshakeState.rawValue + 2)!
        } else if mbedTLS.currentHandshakeState == .handshakeCompleted {
            delegate?.handshakeCompleted()
        } else {
            if mbedtls_ssl_handshake_client_step(&sslContext) == 0 {
                mbedTLS.currentHandshakeState = HandshakeSteps(rawValue: mbedTLS.currentHandshakeState.rawValue + 1)!
                
                switch mbedTLS.currentHandshakeState {
                case .serverKeyExchange:
                    sslContext.session_negotiate.pointee.peer_cert.pointee = sslContext.session_negotiate.pointee.peer_cert.pointee.next.pointee
                case HandshakeSteps.clientCertificate...HandshakeSteps.clientFinished, HandshakeSteps.flushBuffers...HandshakeSteps.handshakeCompleted:
                    executeNextHandshakeStep()
                default:
                    break
                }
            }
        }
    }
    
    public static func parseDerCertificate(_ derCert: [UInt8], chain: inout mbedtls_x509_crt) {
        if mbedtls_x509_crt_parse(&chain, derCert, derCert.count) != 0 {
            print("mbedtls_x509_crt_parse der failed!")
            return
        }
    }
    
    public static func parsePemCertificates(_ concatenatedPemCerts: String, chain: inout mbedtls_x509_crt) {
        let certs = Array(concatenatedPemCerts.utf8)
        let ret = mbedtls_x509_crt_parse(&chain, certs, certs.count)
        if ret != 0 {
            print("mbedtls_x509_crt_parse pem failed! \(ret)")
            return
        }
    }
    
    public static func configureClientCert(with privateKey: inout KeyPair) {
        let ret = mbedtls_ssl_conf_own_cert(&sslConfig, &certChain1, &privateKey)
        if ret != 0 {
            print("mbedtls_ssl_conf_own_cert failed! \(ret)")
        }
    }
    
    public static func configureRootCACert() {
        mbedtls_ssl_conf_ca_chain(&sslConfig, &certChain2, nil)
    }
    
    public static func getDERFromKeyPair(_ keyPair: inout KeyPair) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: 1024)
        let ret = mbedtls_pk_write_key_der(&keyPair, &buffer, 1024)
        if ret >= 0 {
            let bufferStart = buffer.count - Int(ret)
            return Array<UInt8>(buffer[bufferStart...])
        } else {
            return nil
        }
    }
    
    public static func parseKeyPairFromDER(_ bytes: inout [UInt8]) -> Bool {
        mbedTLS.ecKeyPair = mbedtls_pk_context()
        mbedtls_pk_init(&mbedTLS.ecKeyPair)
        let ret = mbedtls_pk_parse_key(&mbedTLS.ecKeyPair, &bytes, bytes.count, nil, 0)
        if ret == 0 {
            return true
        } else {
            return false
        }
    }
    
    public static func write(_ data: inout [UInt8], completion: (() -> Void)? = nil) {
        let ret = mbedtls_ssl_write(&sslContext, &data, data.count)
        if ret < 0 {
            print("mbedtls_ssl_write failed! - \(ret)")
        } else if data.count - Int(ret) != 0 {
            print("mbedtls_ssl_write could not write all data - \(ret)")
        } else {
            if completion != nil {
                completion!()
            }
        }
    }
    
    public static func read(_ data: inout [UInt8], completion: (() -> Void)? = nil) {
        let ret = mbedtls_ssl_read(&sslContext, &data, data.count)
        if ret < 0 {
            print("mbedtls_ssl_read failed! - \(ret)")
        } else {
            if completion != nil {
                completion!()
            }
        }
    }
    
}
