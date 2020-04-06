//
//  HandshakeStep.swift
//  
//
//  Created by Siddarth Gandhi on 4/6/20.
//

import Foundation

public enum HandshakeStep: Int, Strideable {
    case helloRequest = 0, clientHello
    case serverHello, serverCertificate, serverKeyExchange, serverCertificateRequest, serverHelloDone
    case clientCertificate, clientKeyExchange, certificateVerify, clientChangeCipherSpec, clientFinished
    case serverChangeCipherSpec, serverFinished, flushBuffers, handshakeWrapup, handshakeCompleted

    case error = -1

    public typealias Stride = Int

    public func distance(to other: HandshakeStep) -> Int {
        return Stride(other.rawValue) - Stride(self.rawValue)
    }

    public func advanced(by n: Int) -> HandshakeStep {
        return HandshakeStep(rawValue: self.rawValue + n) ?? .error
    }
}
