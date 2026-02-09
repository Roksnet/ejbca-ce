package org.cesecore.keys.token;

import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMapBuilder;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import org.apache.log4j.Logger;

import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;

// Bouncy Castle Imports for Certificate Generation
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;

/**
 * A CryptoToken implementation specifically designed for AWS CloudHSM using the AWS CloudHSM JCE Provider.
 */
public class CaviumCryptoToken implements CryptoToken {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CaviumCryptoToken.class);
    private static final char[] keyStorePassword = "secret".toCharArray();

    private int id;
    private Properties properties;
    private String tokenName = "Cavium";
    private KeyStore keyStore;
    private Provider provider;
    private char[] pin;
    private File keyStoreFile;

    @Override
    public void init(Properties properties, byte[] data, int id) throws Exception {
        this.id = id;
        this.properties = properties;
    }

    @Override
    public void activate(char[] authenticationcode) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        this.pin = authenticationcode; // shallow copy

        try {
            log.info("Initializing CaviumCryptoToken with AWS CloudHsmProvider");

            if (authenticationcode != null) {
                String authStr = new String(authenticationcode);
                String[] parts = authStr.split(":", 2);
                if (parts.length == 2) {
                    System.setProperty("HSM_USER", parts[0]);
                    System.setProperty("HSM_PASSWORD", parts[1]);
                }
            }

            // Add provider if not present
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                this.provider = new CloudHsmProvider();
                Security.addProvider(this.provider);
            } else {
                this.provider = Security.getProvider(CloudHsmProvider.PROVIDER_NAME);
            }            
        } catch (Exception e) {
            log.error("Failed to initialize CloudHSM token", e);
            throw new RuntimeException(e);
        }

        try {
            if (this.keyStore == null) {
                this.keyStore = KeyStore.getInstance(CloudHsmProvider.CLOUDHSM_KEYSTORE_TYPE);
            }
            // Load keystore (try to load file backed certs if available)
            String homeDir = System.getProperty("user.home");
            this.keyStoreFile = new File(homeDir, "cloudhsm-keystore.p12");
            
            if (this.keyStoreFile.exists()) {
                 try (FileInputStream fis = new FileInputStream(this.keyStoreFile)) {
                    this.keyStore.load(fis, keyStorePassword); 
                 }
            } else {
                this.keyStore.load(null, keyStorePassword);
            }

            log.info("CloudHSM Token activated.");

            // --- LOGGING KEYS FOUND ---
            Enumeration<String> aliases = this.keyStore.aliases();
            List<String> foundKeys = new ArrayList<>();
            while (aliases.hasMoreElements()) {
                foundKeys.add(aliases.nextElement());
            }
            
            if (foundKeys.isEmpty()) {
                log.info("HSM Activation successful, but NO keys were found in the slot.");
            } else {
                log.info("HSM Activation successful. Found " + foundKeys.size() + " keys.");
            }
            // --------------------------

        } catch (Exception e) {
            log.error("Failed to activate token", e);
            throw new CryptoTokenAuthenticationFailedException("Failed to activate token: " + e.getMessage());
        }
    }

    @Override
    public void deactivate() {
        this.pin = null;
        this.keyStore = null;
    }

    // --- Key Generation ---

    @Override
    public void generateKeyPair(String keySpec, String alias) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        try {
            log.info("Generating KeyPair (String Spec) for Alias: " + alias);

            String algo = "RSA";
            int keySize = 2048;
            String specUpper = keySpec.toUpperCase();

            // 1. Determine Algo & Size
            if (specUpper.contains("EC") || specUpper.contains("ECDSA")) {
                if (specUpper.contains("384")) keySize = 384;
                else if (specUpper.contains("521")) keySize = 521;
                else keySize = 256;
                
                byte[] ecParams = getEcParams(keySize);
                doGenerateECKeyPair(ecParams, alias); // Helper method
            } else {
                String sizeStr = keySpec.replaceAll("[^0-9]", "");
                if (!sizeStr.isEmpty()) keySize = Integer.parseInt(sizeStr);
                
                doGenerateRSAKeyPair(keySize, alias); // Helper method
            }

        } catch (Exception e) {
            log.error("JCE Generation failed for alias: " + alias, e);
            throw new CryptoTokenOfflineException("JCE Generation failed: " + e.getMessage());
        }
    }

    @Override
    public void generateKeyPair(AlgorithmParameterSpec spec, String alias) throws InvalidAlgorithmParameterException, CertificateException, IOException, CryptoTokenOfflineException {
        try {
            log.info("Generating KeyPair (ParamSpec) for Alias: " + alias);

            if (spec instanceof ECGenParameterSpec) {
                String curveName = ((ECGenParameterSpec) spec).getName();
                byte[] ecParams = getEcParams(curveName);
                doGenerateECKeyPair(ecParams, alias);
            } else if (spec instanceof RSAKeyGenParameterSpec) {
                RSAKeyGenParameterSpec rsaSpec = (RSAKeyGenParameterSpec) spec;
                doGenerateRSAKeyPair(rsaSpec.getKeysize(), alias);
            } else {
                // Fallback / default
                doGenerateRSAKeyPair(2048, alias);
            }

        } catch (Exception e) {
            log.error("JCE Generation failed", e);
            throw new CryptoTokenOfflineException("JCE Generation failed: " + e.getMessage());
        }
    }

    private void doGenerateRSAKeyPair(int keySizeInBits, String alias) throws Exception {
            // Set attributes for RSA public key
            final KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
            publicKeyAttrsMap.put(KeyAttribute.LABEL, alias + ":Public");
            publicKeyAttrsMap.put(KeyAttribute.MODULUS_BITS, keySizeInBits);
            publicKeyAttrsMap.put(KeyAttribute.PUBLIC_EXPONENT, new BigInteger("65537").toByteArray());
            publicKeyAttrsMap.put(KeyAttribute.TOKEN, true);

            // Set attributes for RSA private key
            final KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMap();
            privateKeyAttrsMap.put(KeyAttribute.LABEL, alias); // Using 'alias' for identifying private key in KeyStore
            privateKeyAttrsMap.put(KeyAttribute.TOKEN, true);

            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", CloudHsmProvider.PROVIDER_NAME);
            
            KeyPairAttributesMap keyPairSpec = new KeyPairAttributesMapBuilder()
                    .withPublic(publicKeyAttrsMap)
                    .withPrivate(privateKeyAttrsMap)
                    .build();
            
            keyPairGen.initialize(keyPairSpec);
            KeyPair kp = keyPairGen.generateKeyPair();
            
            // Create dummy cert to ensure EJBCA can see the private key via KeyStore
            createAndStoreDummyCertificate(alias, kp, "RSA");
            log.info("Successfully generated RSA keys and stored dummy certificate for alias: " + alias);
    }

    private void doGenerateECKeyPair(byte[] ecParams, String alias) throws Exception {
            // Set attributes for EC public key
            final KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
            publicKeyAttrsMap.put(KeyAttribute.LABEL, alias + ":Public");
            publicKeyAttrsMap.put(KeyAttribute.EC_PARAMS, ecParams);
            publicKeyAttrsMap.put(KeyAttribute.TOKEN, true);

            // Set attributes for EC private key
            final KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMap();
            privateKeyAttrsMap.put(KeyAttribute.LABEL, alias);
            privateKeyAttrsMap.put(KeyAttribute.TOKEN, true);

            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", CloudHsmProvider.PROVIDER_NAME);
            
            KeyPairAttributesMap keyPairSpec = new KeyPairAttributesMapBuilder()
                    .withPublic(publicKeyAttrsMap)
                    .withPrivate(privateKeyAttrsMap)
                    .build();
            
            keyPairGen.initialize(keyPairSpec);
            KeyPair kp = keyPairGen.generateKeyPair();
            
            createAndStoreDummyCertificate(alias, kp, "EC");
            log.info("Successfully generated EC keys and stored dummy certificate for alias: " + alias);
    }

    public void generateKeyPair(KeyGenParams keyGenParams, String alias) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
       this.generateKeyPair(keyGenParams.getKeySpecification(), alias);
    }

    /**
     * Helper to get DER encoded EC Parameters from a Key Size.
     */
    private byte[] getEcParams(int keySize) throws NoSuchAlgorithmException, InvalidParameterSpecException, IOException {
        String curveName = "secp256r1"; // Default P-256
        if (keySize == 384) curveName = "secp384r1";
        if (keySize == 521) curveName = "secp521r1";
        return getEcParams(curveName);
    }

    /**
     * Helper to get DER encoded EC Parameters from a Curve Name.
     */
    private byte[] getEcParams(String curveName) throws NoSuchAlgorithmException, InvalidParameterSpecException, IOException {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curveName));
        return params.getEncoded();
    }

    /**
     * Helper to create a temporary self-signed certificate and write it to the KeyStore.
     * This makes the Private Key retrievable via the KeyStore API.
     */
    private void createAndStoreDummyCertificate(String alias, KeyPair keyPair, String algorithm) throws Exception {
        try {
            // A. Prepare Certificate Data
            long now = System.currentTimeMillis();
            Date startDate = new Date(now - 1000 * 60 * 60); // 1 hour ago
            Date endDate = new Date(now + 1000L * 60 * 60 * 24 * 365 * 10); // 10 years
            BigInteger serialNumber = BigInteger.valueOf(now);
            
            // X500Name matches the alias to keep it simple
            X500Name subjectAndIssuer = new X500Name("CN=" + alias + ", OU=Temporary CloudHSM Key, O=EJBCA");

            // B. Build the Certificate using Bouncy Castle
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    subjectAndIssuer,
                    serialNumber,
                    startDate,
                    endDate,
                    subjectAndIssuer,
                    keyPair.getPublic()
            );

            // C. Define Signing Algorithm
            String sigAlgo = "SHA256WithRSA";
            if ("EC".equalsIgnoreCase(algorithm) || "ECDSA".equalsIgnoreCase(algorithm)) {
                sigAlgo = "SHA256withECDSA";
            } else if ("DSA".equalsIgnoreCase(algorithm)) {
                sigAlgo = "SHA256withDSA";
            }

            // D. Sign the Certificate using the Private Key (on HSM)
            // Critical: Use the CloudHSM Provider for the signing operation
            ContentSigner signer = new JcaContentSignerBuilder(sigAlgo)
                    .setProvider(CloudHsmProvider.PROVIDER_NAME)
                    .build(keyPair.getPrivate());

            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certBuilder.build(signer));

            // E. Store in KeyStore
            // This links the existing Private Key object with this new Certificate chain
            Certificate[] chain = new Certificate[]{ cert };
            
            // Note: passing 'null' for password is standard for HSM keystores (no key-specific password)
            if (this.keyStore != null) {
                this.keyStore.setKeyEntry(alias, keyPair.getPrivate(), null, chain);
                try (FileOutputStream fos = new FileOutputStream(this.keyStoreFile)) {
                    this.keyStore.store(fos, keyStorePassword); 
                }
            }

        } catch (Exception e) {
            log.error("Failed to create/store dummy certificate for " + alias, e);
            throw new CryptoTokenOfflineException("Failed to persist dummy certificate: " + e.getMessage());
        }
    }

    // --- Standard Methods mapped to keyStore/Provider ---

    @Override
    public List<String> getAliases() throws KeyStoreException, CryptoTokenOfflineException {
        if (keyStore == null) return new ArrayList<>();
        List<String> result = new ArrayList<>();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            result.add(aliases.nextElement());
        }
        return result;
    }

@Override
    public PrivateKey getPrivateKey(String alias) throws CryptoTokenOfflineException {
        try {
            if (keyStore == null) {
                log.info("DEBUG: getPrivateKey('" + alias + "') -> KeyStore is null");
                return null;
            }

            // Retrieve key as generic Key first to debug before casting
            Key key = keyStore.getKey(alias, pin);

            if (key == null) {
                log.info("DEBUG: getPrivateKey('" + alias + "') -> returned NULL from KeyStore");
            } else {
                log.info("DEBUG: getPrivateKey('" + alias + "') -> returned object of type: " + key.getClass().getName());
            }

            return (PrivateKey) key;
        } catch (Exception e) {
            log.error("Error fetching private key for alias: " + alias, e);
            return null;
        }
    }

    @Override
    public boolean doesPrivateKeyExist(String alias) {
        try {
            // This will trigger the debug log in getPrivateKey
            return this.getPrivateKey(alias) != null;
        } catch (CryptoTokenOfflineException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public PublicKey getPublicKey(String alias) throws CryptoTokenOfflineException {
        try {
            if (keyStore == null) {
                log.info("DEBUG: getPublicKey('" + alias + "') -> KeyStore is null");
                return null;
            }

            Certificate cert = keyStore.getCertificate(alias);

            if (cert == null) {
                log.info("DEBUG: getPublicKey('" + alias + "') -> Certificate is NULL for alias");
                return null;
            }

            PublicKey pubKey = cert.getPublicKey();
            
            if (pubKey == null) {
                log.info("DEBUG: getPublicKey('" + alias + "') -> Certificate found, but PublicKey is NULL");
            } else {
                log.info("DEBUG: getPublicKey('" + alias + "') -> returned PublicKey of type: " + pubKey.getClass().getName());
            }

            return pubKey;
        } catch (Exception e) {
            log.error("Error fetching public key for alias: " + alias, e);
            return null;
        }
    }
    
    @Override
    public Key getKey(String alias) throws CryptoTokenOfflineException {
        return getPrivateKey(alias);
    }
    
    // Required interface methods
    
    @Override public void deleteEntry(String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, CryptoTokenOfflineException {
        if (keyStore != null) {
            try {
                Key key = keyStore.getKey(alias, keyStorePassword);
                if (key instanceof javax.security.auth.Destroyable) { 
                    ((javax.security.auth.Destroyable) key).destroy();
                    log.info("Destroyed key material for alias: " + alias);
                }
            } catch (Exception e) {
                log.warn("Failed to destroy key for alias: " + alias, e);
            }

            try {
                Key key = keyStore.getKey(alias + ":Public", keyStorePassword);
                if (key instanceof javax.security.auth.Destroyable) {
                    ((javax.security.auth.Destroyable) key).destroy();
                    log.info("Destroyed key material for alias: " + alias + ":Public");
                }
            } catch (Exception e) {
                log.warn("Failed to destroy public key for alias: " + alias, e);
            }
            
            try {
                keyStore.deleteEntry(alias);
            } catch (Exception e) {
                // CloudHSM JCE might throw if the key was already destroyed or if it only supports cert deletion
                log.warn("Failed to delete entry from keystore (cert): " + alias + ": " + e.getMessage());
            }

            try (FileOutputStream fos = new FileOutputStream(this.keyStoreFile)) {
                this.keyStore.store(fos, keyStorePassword);
            }
        }
    }
    
    @Override public boolean doPermitExtractablePrivateKey() { return false; }
    @Override public String getEncProviderName() { return CloudHsmProvider.PROVIDER_NAME; }
    @Override public int getId() { return id; }
    @Override public String getTokenName() { return tokenName; }
    @Override public void setTokenName(String tokenName) { this.tokenName = tokenName; }
    @Override public boolean isAliasUsed(String alias) { 
        try { return keyStore != null && keyStore.containsAlias(alias); } catch (Exception e) { return false; } 
    }
    @Override public Properties getProperties() { return properties; }
    @Override public String getSignProviderName() { return CloudHsmProvider.PROVIDER_NAME; }
    @Override public byte[] getTokenData() { return null; }
    @Override public int getTokenStatus() { return keyStore != null ? 1 : 0; }
    @Override public void reset() { }
    @Override public void setProperties(Properties properties) { this.properties = properties; }
    
    @Override 
    public void testKeyPair(String alias) throws InvalidKeyException, CryptoTokenOfflineException { 
        PublicKey publicKey = getPublicKey(alias);
        PrivateKey privateKey = getPrivateKey(alias);
        if (publicKey == null || privateKey == null) {
             throw new InvalidKeyException("KeyPair not found for alias: " + alias);
        }
        testKeyPair(alias, publicKey, privateKey);
    }
    
    @Override 
    public void testKeyPair(String alias, PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException { 
        try {
            // Simple sign/verify test
            String sigAlgo = "SHA256WithRSA";
            if (publicKey.getAlgorithm().contains("EC")) {
                sigAlgo = "SHA256WithECDSA";
            }
            // Use the HSM provider for signing
            Signature signature = Signature.getInstance(sigAlgo, getSignProviderName()); 
            signature.initSign(privateKey);
            String tbs = "EJBCA Test " + alias;
            signature.update(tbs.getBytes());
            byte[] sig = signature.sign();
            
            // Verify using standard BC provider
            Signature verify = Signature.getInstance(sigAlgo, "BC");
            verify.initVerify(publicKey);
            verify.update(tbs.getBytes());
            if (!verify.verify(sig)) {
                throw new InvalidKeyException("Signature verification failed for alias: " + alias);
            }
            log.info("KeyPair test successful for alias: " + alias);

        } catch (Exception e) {
            log.error("KeyPair test failed for alias: " + alias, e);
            throw new InvalidKeyException("KeyPair test failed: " + e.getMessage());
        }
    }
    
    @Override public void storeKey(String alias, Key key, Certificate[] chain, char[] password) throws KeyStoreException {
         if (keyStore != null) {
             keyStore.setKeyEntry(alias, key, password, chain);
             try (FileOutputStream fos = new FileOutputStream(this.keyStoreFile)) {
                 this.keyStore.store(fos, keyStorePassword);
             } catch (Exception e) {
                 throw new KeyStoreException("Failed to store keystore: " + e.getMessage(), e);
             }
         }
    }
    @Override public boolean isAutoActivationPinPresent() { return false; }
    @Override public Set<Long> getKeyUsagesFromKey(String alias, boolean b, long... longs) { return new HashSet<>(); }
    @Override public Set<Long> getKeyUsagesFromPrivateKey(String alias) { return new HashSet<>(); }
    @Override public Set<Long> getKeyUsagesFromPublicKey(String alias) { return new HashSet<>(); }
    
    @Override
    public void generateKey(String algorithm, int keysize, String alias) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException, CertificateException, IOException, NoSuchPaddingException, IllegalBlockSizeException {
        log.info("Generating Symmetric Key: " + alias + " Algo: " + algorithm + " Size: " + keysize);
        
        try {
            if (this.keyStore == null) {
                throw new CryptoTokenOfflineException("Keystore not initialized");
            }
            
            // CloudHSM JCE supports AES, generic secret keys, etc.
            KeyGenerator kg = KeyGenerator.getInstance(algorithm, CloudHsmProvider.PROVIDER_NAME);
            kg.init(keysize);
            SecretKey sk = kg.generateKey();
            
            keyStore.setKeyEntry(alias, sk, null, null);
            
            try (FileOutputStream fos = new FileOutputStream(this.keyStoreFile)) {
                 this.keyStore.store(fos, keyStorePassword); 
            }
            log.info("Symmetric key generated and stored: " + alias);
            
        } catch (Exception e) {
            log.error("Failed to generate symmetric key " + alias, e);
            throw new KeyStoreException("Failed to generate symmetric key: " + e.getMessage(), e);
        }
    }
    
    @Override
    public void keyAuthorizeInit(String alias, KeyPair kakKeyPair, String signProviderName, String selectedPaddingScheme) { }
    @Override
    public void keyAuthorize(String alias, KeyPair kakPair, String signProviderName, long maxOperationCount, String selectedPaddingScheme) { }
    @Override
    public void changeAuthData(String alias, KeyPair currentKakPair, KeyPair newKakPair, String signProviderName, String selectedPaddingScheme) { }
    @Override
    public boolean isKeyInitialized(String alias) { return true; }
    @Override
    public long maxOperationCount(String alias) { return Long.MAX_VALUE; }
    @Override
    public void backupKey(int keySpecId, Path backupFilePath) { }
    @Override
    public void restoreKey(int keySpecId, Path backupFilePath) { }

}
