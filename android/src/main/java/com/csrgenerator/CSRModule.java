package com.csrgenerator;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.StringWriter;

public class CSRModule extends ReactContextBaseJavaModule {
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String ALIAS = "CSR_GENERATOR_ECC_KEY_ALIAS";

    public CSRModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "CSRGenerator";
    }

    @ReactMethod
    public void generateECCKeyPair(Promise promise) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            ALIAS,
                            KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .build());

            keyPairGenerator.generateKeyPair();
            promise.resolve("ECC key pair generated successfully");
        } catch (Exception e) {
            promise.reject("ECC_ERROR", "Failed to generate ECC key pair: " + e.getMessage());
        }
    }

    @ReactMethod
    public void generateCSR(
            String cn,
            String userId,
            String country,
            String state,
            String locality,
            String organization,
            String organizationalUnit,
            Promise promise) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(ALIAS, null);
            PublicKey publicKey = keyStore.getCertificate(ALIAS).getPublicKey();

            String csr = createCSR(cn, userId, country, state, locality, organization, organizationalUnit, privateKey, publicKey);
            promise.resolve(csr);
        } catch (Exception e) {
            promise.reject("CSR_ERROR", "Failed to generate CSR: " + e.getMessage());
        }
    }

    private String createCSR(
            String cn,
            String userId,
            String country,
            String state,
            String locality,
            String organization,
            String organizationalUnit,
            PrivateKey privateKey,
            PublicKey publicKey) throws Exception {
        // Build X.500Name with subject information
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        if (cn != null && !cn.isEmpty()) {
            nameBuilder.addRDN(BCStyle.CN, cn);
        }
        if (userId != null && !userId.isEmpty()) {
            nameBuilder.addRDN(BCStyle.UID, userId);
        }
        if (country != null && !country.isEmpty()) {
            nameBuilder.addRDN(BCStyle.C, country);
        }
        if (state != null && !state.isEmpty()) {
            nameBuilder.addRDN(BCStyle.ST, state);
        }
        if (locality != null && !locality.isEmpty()) {
            nameBuilder.addRDN(BCStyle.L, locality);
        }
        if (organization != null && !organization.isEmpty()) {
            nameBuilder.addRDN(BCStyle.O, organization);
        }
        if (organizationalUnit != null && !organizationalUnit.isEmpty()) {
            nameBuilder.addRDN(BCStyle.OU, organizationalUnit);
        }

        // Convert public key to SubjectPublicKeyInfo
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        // Build PKCS#10 CSR
        PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(
                nameBuilder.build(), subjectPublicKeyInfo);
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
        var csr = csrBuilder.build(signerBuilder.build(privateKey));

        // Convert to PEM format
        StringWriter stringWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(stringWriter)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
        }
        return stringWriter.toString();
    }
}