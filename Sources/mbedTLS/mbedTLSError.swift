//
//  mbedTLSError.swift
//  
//
//  Created by Siddarth Gandhi on 4/6/20.
//

import Foundation

public enum mbedTLSError: LocalizedError {
    case entropy
    case privateKeySetup
    case keyPairGeneration
    case parsingSubjectName
    case csrGeneration
    case sslConfiguration
    case sslSetup
    case handshakeStep(errorCode: Int)
    case parseCertificate
    case configureClientCertificate
    case keyPairToDER
    case parseKeyPair
    case write(errorCode: Int)
    case read(errorCode: Int)

    public var errorDescription: String? {
        switch self {
        case .entropy:
            return "Entropy setup failed. (mbedtls_ctr_drbg_seed)"
        case .privateKeySetup:
            return "Initializing PK Context failed. (mbedtls_pk_setup)"
        case .keyPairGeneration:
            return "ECP Key generation failed. (mbedtls_ecp_gen_key)"
        case .parsingSubjectName:
            return "Failed to parse CSR subject name. (mbedtls_x509write_csr_set_subject_name)"
        case .csrGeneration:
            return "Failed to generate a CSR. (mbedtls_x509write_csr_pem)"
        case .sslConfiguration:
            return "Loading SSL configuration values failed. (mbedtls_ssl_config_defaults)"
        case .sslSetup:
            return "Setting up SSL Context failed. (mbedtls_ssl_setup)"
        case .handshakeStep:
            return "Failed to execute handshake step. (mbedtls_ssl_handshake_client_step)"
        case .parseCertificate:
            return "Parsing certificates failed. (mbedtls_x509_crt_parse)"
        case .configureClientCertificate:
            return "Configuring client certificate failed. (mbedtls_ssl_conf_own_cert)"
        case .keyPairToDER:
            return "Failed to write DER bytes from the key pair. (mbedtls_pk_write_key_der)"
        case .parseKeyPair:
            return "Parsing key pair failed. (mbedtls_pk_parse_key)"
        case .write:
            return "Write failed. (mbedtls_ssl_write)"
        case .read:
            return "Read failed. (mbedtls_ssl_read)"
        }
    }
}
