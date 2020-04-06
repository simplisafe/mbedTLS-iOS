//
//  mbedTLSError.swift
//  
//
//  Created by Siddarth Gandhi on 4/6/20.
//

import Foundation

public enum mbedTLSError: String, Error {
    case entropy = "Entropy setup failed. (mbedtls_ctr_drbg_seed)"
    case privateKeySetup = "Initializing PK Context failed. (mbedtls_pk_setup)"
    case keyPairGeneration = "ECP Key generation failed. (mbedtls_ecp_gen_key)"
    case parsingSubjectName = "Failed to parse CSR subject name. (mbedtls_x509write_csr_set_subject_name)"
    case csrGeneration = "Failed to generate a CSR. (mbedtls_x509write_csr_pem)"
    case sslConfiguration = "Loading SSL configuration values failed. (mbedtls_ssl_config_defaults)"
    case sslSetup = "Setting up SSL Context failed. (mbedtls_ssl_setup)"
    case handshakeStep = "Failed to execute handshake step. (mbedtls_ssl_handshake_client_step)"
    case parseCertificate = "Parsing certificates failed. (mbedtls_x509_crt_parse)"
    case configureClientCertificate = "Configuring client certificate failed. (mbedtls_ssl_conf_own_cert)"
    case keyPairToDER = "Failed to write DER bytes from the key pair. (mbedtls_pk_write_key_der)"
    case parseKeyPair = "Parsing key pair failed. (mbedtls_pk_parse_key)"
    case write = "Write failed. (mbedtls_ssl_write)"
    case read = "Read failed. (mbedtls_ssl_read)"
}
