//
//  mbedTLS.swift
//  mbedTLS
//
//  Created by Siddarth Gandhi on 2/21/19.
//  Copyright © 2019 SimpliSafe. All rights reserved.
//

import Foundation
import libmbedtls

public class mbedTLS {
    
    public enum HandshakeSteps: Int32 {
        case helloRequest = 0, clientHello
        case serverHello, serverCertificate, serverKeyExchange, serverCertificateRequest, serverHelloDone
        case clientCertificate, clientKeyExchange, certificateVerify, clientFinished
        case serverFinished
    }
    
    public enum SSLProtocolVersion: Int32 {
        case sslProtocol10 = 1
        case sslProtocol11 = 2
        case sslProtocol12 = 3
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
    
    public static var readCallbackBuffer: [UInt8]?
    
    public typealias sslWriteCallback = (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int) ->  Int32
    public typealias sslReadCallback = (UnsafeMutableRawPointer?, UnsafeMutablePointer<UInt8>?, Int) ->  Int32
    
    static var sslWriteCallbackFunc: sslWriteCallback!
    static var sslReadCallbackFunc: sslReadCallback!
    
    public static var currentHandshakeState: HandshakeSteps = .helloRequest
    
    static var ciphers: Array<Int32>!
    
    public static func setupSSLContext() {
        sslContext = mbedtls_ssl_context()
        sslConfig = mbedtls_ssl_config()
        counterRandomByteGenerator = mbedtls_ctr_drbg_context()
        entropy = mbedtls_entropy_context()
        certChain1 = mbedtls_x509_crt()
        certChain2 = mbedtls_x509_crt()
        
        mbedtls_ssl_init(&sslContext)
        mbedtls_ssl_config_init(&sslConfig)
        mbedtls_ctr_drbg_init(&counterRandomByteGenerator)
        mbedtls_entropy_init(&entropy)
        mbedtls_x509_crt_init(&certChain1)
        mbedtls_x509_crt_init(&certChain2)
        
        if mbedtls_ctr_drbg_seed(&counterRandomByteGenerator, mbedtls_entropy_func, &entropy, nil, 0) != 0 {
            print("mbedtls_ctr_drbg_seed failed!")
            return
        }
        
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
        if mbedTLS.currentHandshakeState == .serverFinished {
            return
        }
        
        if mbedTLS.currentHandshakeState == .helloRequest {
            mbedtls_ssl_handshake_client_step(&sslContext)
            mbedtls_ssl_handshake_client_step(&sslContext)
            mbedTLS.currentHandshakeState = HandshakeSteps(rawValue: mbedTLS.currentHandshakeState.rawValue + 2)!
        } else {
            if mbedtls_ssl_handshake_client_step(&sslContext) == 0 {
                mbedTLS.currentHandshakeState = HandshakeSteps(rawValue: mbedTLS.currentHandshakeState.rawValue + 1)!
                
                switch sslContext.state {
                case HandshakeSteps.serverKeyExchange.rawValue:
                    sslContext.session_negotiate.pointee.peer_cert.pointee = sslContext.session_negotiate.pointee.peer_cert.pointee.next.pointee
                case HandshakeSteps.clientCertificate.rawValue...HandshakeSteps.clientFinished.rawValue:
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
    
    public static func configureClientCert(with privateKey: SecKey) {
        let ret = mbedtls_ssl_conf_own_cert(&sslConfig, &certChain1, nil)
        if ret != 0 {
            print("mbedtls_ssl_conf_own_cert failed! \(ret)")
        }
    }
    
    public static func configureRootCACert() {
        mbedtls_ssl_conf_ca_chain(&sslConfig, &certChain2, nil)
    }
    
}
