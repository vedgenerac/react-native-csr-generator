import CryptoKit
import Foundation
import OpenSSLHelper

@objc(CSRGenerator)
class CSRGenerator: NSObject {
    
    @objc
    static func requiresMainQueueSetup() -> Bool {
        return false
    }
    
    @objc
    func generateECCKeyPair(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        // For iOS, we generate the key pair on-demand during CSR generation
        // CryptoKit doesn't use persistent keychain storage like Android KeyStore
        resolve("ECC key pair will be generated during CSR creation")
    }
    
    @objc
    func generateCSR(
        _ cn: String?,
        userId: String?,
        country: String?,
        state: String?,
        locality: String?,
        organization: String?,
        organizationalUnit: String?,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        // Prepare subject info dictionary
        var subjectInfo: [String: Any] = [:]
        if let cn = cn, !cn.isEmpty { subjectInfo["CN"] = cn }
        if let userId = userId, !userId.isEmpty { subjectInfo["userId"] = userId }
        if let country = country, !country.isEmpty { subjectInfo["country"] = country }
        if let state = state, !state.isEmpty { subjectInfo["state"] = state }
        if let locality = locality, !locality.isEmpty { subjectInfo["locality"] = locality }
        if let organization = organization, !organization.isEmpty { subjectInfo["organization"] = organization }
        if let organizationalUnit = organizationalUnit, !organizationalUnit.isEmpty { 
            subjectInfo["organizationalUnitName"] = organizationalUnit 
        }
        
        var error: NSError?
        guard let csr = generateCSR(withSubjectInfo: subjectInfo, error: &error) else {
            let errorMessage = error?.localizedDescription ?? "Failed to generate CSR"
            reject("CSR_ERROR", errorMessage, error)
            return
        }
        
        resolve(csr)
    }
    
    private func generateCSR(withSubjectInfo subjectInfo: [String: Any], error outError: NSErrorPointer) -> String? {
        // Validate Common Name (CN)
        guard let commonName = subjectInfo["CN"] as? String, !commonName.isEmpty else {
            if let errorPointer = outError {
                errorPointer.pointee = NSError(domain: "CSRGenerationError", code: -1, userInfo: [
                    NSLocalizedDescriptionKey: "Common Name (CN) is required and cannot be empty."
                ])
            }
            return nil
        }
        
        // Extract other subject info with defaults
        let userId = subjectInfo["userId"] as? String ?? ""
        let country = subjectInfo["country"] as? String ?? ""
        let state = subjectInfo["state"] as? String ?? ""
        let locality = subjectInfo["locality"] as? String ?? ""
        let organization = subjectInfo["organization"] as? String ?? ""
        let organizationalUnitName = subjectInfo["organizationalUnitName"] as? String ?? ""
        
        do {
            // Generate ECC 256-bit private key using CryptoKit (P-256 curve)
            let privateKey = P256.Signing.PrivateKey()
            let publicKey = privateKey.publicKey
            
            // Convert CryptoKit keys to DER format
            let privateKeyDER = privateKey.rawRepresentation
            let publicKeyDER = publicKey.rawRepresentation
            
            // Convert to OpenSSL EVP_PKEY
            guard let privateKeyPtr = privateKeyDER.withUnsafeBytes({ ptr in
                convert_to_evp_pkey(UnsafeMutablePointer(mutating: ptr.baseAddress!.assumingMemoryBound(to: UInt8.self)), Int32(privateKeyDER.count), 1)
            }) else {
                throw NSError(domain: "CSRGenerationError", code: -2, userInfo: [
                    NSLocalizedDescriptionKey: "Failed to convert private key to EVP_PKEY."
                ])
            }
            
            // Create X509 request
            guard let x509Req = create_x509_request() else {
                cleanup_evp_pkey(privateKeyPtr)
                throw NSError(domain: "CSRGenerationError", code: -3, userInfo: [
                    NSLocalizedDescriptionKey: "Failed to create X509 request."
                ])
            }
            
            // Set public key
            let success = publicKeyDER.withUnsafeBytes { ptr in
                set_public_key(x509Req, UnsafeMutablePointer(mutating: ptr.baseAddress!.assumingMemoryBound(to: UInt8.self)), Int32(publicKeyDER.count))
            }
            guard success != 0 else {
                cleanup_x509_request(x509Req)
                cleanup_evp_pkey(privateKeyPtr)
                throw NSError(domain: "CSRGenerationError", code: -4, userInfo: [
                    NSLocalizedDescriptionKey: "Failed to set public key."
                ])
            }
            
            // Build subject name
            guard let subjectName = create_x509_name() else {
                cleanup_x509_request(x509Req)
                cleanup_evp_pkey(privateKeyPtr)
                throw NSError(domain: "CSRGenerationError", code: -5, userInfo: [
                    NSLocalizedDescriptionKey: "Failed to create X509 name."
                ])
            }
            
            // Add subject name entries
            try addX509NameEntry(subjectName, field: "CN", value: commonName)
            if !country.isEmpty { try addX509NameEntry(subjectName, field: "C", value: country) }
            if !state.isEmpty { try addX509NameEntry(subjectName, field: "ST", value: state) }
            if !locality.isEmpty { try addX509NameEntry(subjectName, field: "L", value: locality) }
            if !organization.isEmpty { try addX509NameEntry(subjectName, field: "O", value: organization) }
            if !organizationalUnitName.isEmpty { try addX509NameEntry(subjectName, field: "OU", value: organizationalUnitName) }
            if !userId.isEmpty { try addX509NameEntry(subjectName, field: "UID", value: userId) }
            
            // Set subject name
            guard set_subject_name(x509Req, subjectName) != 0 else {
                cleanup_x509_name(subjectName)
                cleanup_x509_request(x509Req)
                cleanup_evp_pkey(privateKeyPtr)
                throw NSError(domain: "CSRGenerationError", code: -6, userInfo: [
                    NSLocalizedDescriptionKey: "Failed to set subject name."
                ])
            }
            
            // Sign the CSR
            guard sign_x509_request(x509Req, privateKeyPtr) != 0 else {
                cleanup_x509_name(subjectName)
                cleanup_x509_request(x509Req)
                cleanup_evp_pkey(privateKeyPtr)
                throw NSError(domain: "CSRGenerationError", code: -7, userInfo: [
                    NSLocalizedDescriptionKey: "Failed to sign CSR."
                ])
            }
            
            // Export CSR to DER
            var derLength: Int32 = 0
            guard let derPtr = export_csr_to_der(x509Req, &derLength) else {
                cleanup_x509_name(subjectName)
                cleanup_x509_request(x509Req)
                cleanup_evp_pkey(privateKeyPtr)
                throw NSError(domain: "CSRGenerationError", code: -8, userInfo: [
                    NSLocalizedDescriptionKey: "Failed to export CSR to DER."
                ])
            }
            let csrData = Data(bytes: derPtr, count: Int(derLength))
            free(derPtr)
            
            // Convert to PEM
            let csrBase64 = csrData.base64EncodedString(options: .lineLength64Characters)
            let pem = "-----BEGIN CERTIFICATE REQUEST-----\n\(csrBase64)\n-----END CERTIFICATE REQUEST-----"
            
            // Clean up
            cleanup_x509_name(subjectName)
            cleanup_x509_request(x509Req)
            cleanup_evp_pkey(privateKeyPtr)
            
            return pem
        } catch {
            if let errorPointer = outError {
                errorPointer.pointee = error as NSError
            }
            return nil
        }
    }
    
    private func addX509NameEntry(_ name: OpaquePointer, field: String, value: String) throws {
        let result = field.withCString { fieldPtr in
            value.withCString { valuePtr in
                add_x509_name_entry(name, fieldPtr, valuePtr)
            }
        }
        guard result != 0 else {
            throw NSError(domain: "CSRGenerationError", code: -9, userInfo: [
                NSLocalizedDescriptionKey: "Failed to add X509 name entry for \(field)."
            ])
        }
    }
}