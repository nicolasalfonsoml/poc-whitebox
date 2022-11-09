package com.example.whitboxwithjni;


import static com.google.android.attestation.Constants.GOOGLE_ROOT_CERTIFICATE;
import static com.google.android.attestation.ParsedAttestationRecord.createParsedAttestationRecord;
import static java.nio.charset.StandardCharsets.UTF_8;

import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.StrictMode;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.SecureKeyImportUnavailableException;
import android.security.keystore.WrappedKeyEntry;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.example.whitboxwithjni.databinding.ActivityMainBinding;
import com.google.android.attestation.AttestationApplicationId;
import com.google.android.attestation.AuthorizationList;
import com.google.android.attestation.CertificateRevocationStatus;
import com.google.android.attestation.ParsedAttestationRecord;
import com.google.android.attestation.RootOfTrust;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;


public class MainActivityBackup extends AppCompatActivity {

    private String logMsg = "";
    private ActivityMainBinding binding;

    private static final String TAG = "ImportWrappedKeyTest";
    private static final String ALIAS = "my key";
    private static final String WRAPPING_KEY_ALIAS = "my_favorite_wrapping_key";
    private static final int WRAPPED_FORMAT_VERSION = 0;
    private static final int GCM_TAG_SIZE = 128;

    // https://source.android.com/reference/hal/globals_eval_k
    // https://android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/keymaster_defs.h
    private static final int KM_KEY_FORMAT_RAW = 3; /* for symmetric key import and export*/
    private static final int KM_ALGORITHM_AES = 32;
    private static final int KM_MODE_CBC = 2;
    private static final int KM_MODE_ECB = 1;
    private static final int KM_PAD_NONE = 1; /* deprecated */
    private static final int KM_PAD_PKCS7 = 64;
    private static final int KM_PURPOSE_DECRYPT = 1;
    private static final int KM_PURPOSE_ENCRYPT = 0;

    SecureRandom random = new SecureRandom();

    boolean hasStrongBox() {
        return this.getPackageManager()
                .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
    }

    void addLog(String msg){
        logMsg+= "\n" + msg;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        addLog("Init...");

        // para ejecutar un request en el hilo principal
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        //TextView tv = binding.sampleText;

        String KEY_ALIAS = "attestationTest";
        String ANDROID_KEYSTORE = "AndroidKeyStore";

        random.setSeed(0);
        byte[] keyMaterial = new byte[16];
        random.nextBytes(keyMaterial);

        byte[] mask = new byte[32]; // Zero mask, optional
        random.nextBytes(mask);

        byte[] challengeBytes = new byte[128]; // attestation challenge

        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null, null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        KeyPair kp = null;
        KeyGenParameterSpec KeyGenParameterSpec = null;
        try {
            kp = genKeyPair(WRAPPING_KEY_ALIAS, challengeBytes);
        } catch (SecureKeyImportUnavailableException e){
            e.printStackTrace();
            addLog("SecureKeyImportUnavailableException!!!: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            addLog("Exception!!!: " + e.getMessage());
        }

        // get certificate pk and send to BE
        //getCertAndSendToBE(keyStore,KEY_ALIAS);

        try {
            byte[] wrapKeyBE = wrapKey(kp.getPublic(), keyMaterial, mask,
                    makeAuthList(keyMaterial.length * 8, KM_ALGORITHM_AES));
            importWrappedKey(keyStore, WRAPPING_KEY_ALIAS, wrapKeyBE);
        } catch (SecureKeyImportUnavailableException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            cipherKS(keyStore, ALIAS);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

       // tv.setText(logMsg);

    }

    private void getCertAndSendToBE(KeyStore ks, String KeyAlias) throws KeyStoreException{
        Certificate[] certs = ks.getCertificateChain(KeyAlias);
        X509Certificate[] x509certs = new X509Certificate[certs.length];
        for (int i = 0; i < x509certs.length; i++) {
            X509Certificate cert = (X509Certificate) certs[i];
            x509certs[i] = cert;
        }
    }

    private void cipherKS(KeyStore ks, String KeyAlias)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

        Key key = ks.getKey(KeyAlias, null);
        if(key == null){
            addLog("No se proceso el wrapper key");
            return;
        }

        Cipher c = Cipher.getInstance("AES/ECB/PKCS7Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = c.doFinal("hello, world".getBytes());

        c = Cipher.getInstance("AES/ECB/PKCS7Padding");
        c.init(Cipher.DECRYPT_MODE, key);
        String decrypted = new String(c.doFinal(encrypted));

        System.out.println("encrypted hex:: " + bytesToHex(encrypted));

        addLog("decrypted:: " + decrypted);
    }

    private boolean existKey(KeyStore ks, String keyAlias)
            throws KeyStoreException,NoSuchAlgorithmException,UnrecoverableKeyException{
        Key keyExist = ks.getKey(keyAlias, null);
        System.out.println("keyExist");
        System.out.println(keyExist);
        if(keyExist != null){
            return true;
        }
        return false;
    }

    private void printSecurityInfo(X509Certificate[] x509certs){
        ParsedAttestationRecord parsedAttestationRecord = null;
        try {
            parsedAttestationRecord = createParsedAttestationRecord(x509certs[0]);
        } catch (IOException e) {
            e.printStackTrace();
        }
        addLog("---------------------");
        addLog("Attestation parsed ...");


        addLog("Attestation version: " + parsedAttestationRecord.attestationVersion);
        addLog(
                "Attestation Security Level: " + parsedAttestationRecord.attestationSecurityLevel.name());
        addLog("Keymaster Version: " + parsedAttestationRecord.keymasterVersion);
        addLog(
                "Keymaster Security Level: " + parsedAttestationRecord.keymasterSecurityLevel.name());

        addLog("---------------------");
        addLog("Software Enforced Authorization List:");
        AuthorizationList softwareEnforced = parsedAttestationRecord.softwareEnforced;
        printAuthorizationList(softwareEnforced, "\t");

        addLog("---------------------");
        addLog("TEE Enforced Authorization List:");
        AuthorizationList teeEnforced = parsedAttestationRecord.teeEnforced;
        printAuthorizationList(teeEnforced, "\t");
    }

    private void printAuthorizationList(AuthorizationList authorizationList, String indent) {
        // Detailed explanation of the keys and their values can be found here:
        // https://source.android.com/security/keystore/tags
        printOptional(authorizationList.purpose, indent + "Purpose(s)");
        printOptional(authorizationList.algorithm, indent + "Algorithm");
        printOptional(authorizationList.keySize, indent + "Key Size");
        printOptional(authorizationList.digest, indent + "Digest");
        printOptional(authorizationList.padding, indent + "Padding");
        printOptional(authorizationList.ecCurve, indent + "EC Curve");
        printOptional(authorizationList.rsaPublicExponent, indent + "RSA Public Exponent");
        addLog(indent + "Rollback Resistance: " + authorizationList.rollbackResistance);
        printOptional(authorizationList.activeDateTime, indent + "Active DateTime");
        printOptional(
                authorizationList.originationExpireDateTime, indent + "Origination Expire DateTime");
        printOptional(authorizationList.usageExpireDateTime, indent + "Usage Expire DateTime");
        addLog(indent + "No Auth Required: " + authorizationList.noAuthRequired);
        printOptional(authorizationList.userAuthType, indent + "User Auth Type");
        printOptional(authorizationList.authTimeout, indent + "Auth Timeout");
        addLog(indent + "Allow While On Body: " + authorizationList.allowWhileOnBody);
        addLog(
                indent
                        + "Trusted User Presence Required: "
                        + authorizationList.trustedUserPresenceRequired);
        addLog(
                indent + "Trusted Confirmation Required: " + authorizationList.trustedConfirmationRequired);
        addLog(
                indent + "Unlocked Device Required: " + authorizationList.unlockedDeviceRequired);
        addLog(indent + "All Applications: " + authorizationList.allApplications);
        printOptional(authorizationList.applicationId, indent + "Application ID");
        printOptional(authorizationList.creationDateTime, indent + "Creation DateTime");
        printOptional(authorizationList.origin, indent + "Origin");
        addLog(indent + "Rollback Resistant: " + authorizationList.rollbackResistant);
        if (authorizationList.rootOfTrust.isPresent()) {
            addLog(indent + "Root Of Trust:");
            printRootOfTrust(authorizationList.rootOfTrust, indent + "\t");
        }
        printOptional(authorizationList.osVersion, indent + "OS Version");
        printOptional(authorizationList.osPatchLevel, indent + "OS Patch Level");
        if (authorizationList.attestationApplicationId.isPresent()) {
            addLog(indent + "Attestation Application ID:");
            printAttestationApplicationId(authorizationList.attestationApplicationId, indent + "\t");
        }
        printOptional(
                authorizationList.attestationApplicationIdBytes,
                indent + "Attestation Application ID Bytes");
        printOptional(authorizationList.attestationIdBrand, indent + "Attestation ID Brand");
        printOptional(authorizationList.attestationIdDevice, indent + "Attestation ID Device");
        printOptional(authorizationList.attestationIdProduct, indent + "Attestation ID Product");
        printOptional(authorizationList.attestationIdSerial, indent + "Attestation ID Serial");
        printOptional(authorizationList.attestationIdImei, indent + "Attestation ID IMEI");
        printOptional(authorizationList.attestationIdMeid, indent + "Attestation ID MEID");
        printOptional(
                authorizationList.attestationIdManufacturer, indent + "Attestation ID Manufacturer");
        printOptional(authorizationList.attestationIdModel, indent + "Attestation ID Model");
        printOptional(authorizationList.vendorPatchLevel, indent + "Vendor Patch Level");
        printOptional(authorizationList.bootPatchLevel, indent + "Boot Patch Level");
    }

    private boolean insideSecureHardware(KeyPair key){
        KeyFactory factory = null;
        KeyInfo keyInfo = null;
        try {
            factory = KeyFactory.getInstance(key.getPrivate().getAlgorithm(), "AndroidKeyStore");
            keyInfo = factory.getKeySpec(key.getPrivate(), KeyInfo.class);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        if (keyInfo.isInsideSecureHardware()) {
            return true;
        }
        return false;
    }

    private void printRootOfTrust(Optional<RootOfTrust> rootOfTrust, String indent) {
        if (rootOfTrust.isPresent()) {
            addLog(
                    indent
                            + "Verified Boot Key: "
                            + Base64.toBase64String(rootOfTrust.get().verifiedBootKey));
            addLog(indent + "Device Locked: " + rootOfTrust.get().deviceLocked);
            addLog(
                    indent + "Verified Boot State: " + rootOfTrust.get().verifiedBootState.name());
            if(rootOfTrust.get().verifiedBootHash != null) {
                addLog(
                        indent
                                + "Verified Boot Hash: "
                                + Base64.toBase64String(rootOfTrust.get().verifiedBootHash));
            }
        }
    }

    private void printAttestationApplicationId(
            Optional<AttestationApplicationId> attestationApplicationId, String indent) {
        if (attestationApplicationId.isPresent()) {
            addLog(indent + "Package Infos (<package name>, <version>): ");
            for (AttestationApplicationId.AttestationPackageInfo info : attestationApplicationId.get().packageInfos) {
                addLog(indent + "\t" + info.packageName + ", " + info.version);
            }
            addLog(indent + "Signature Digests:");
            for (byte[] digest : attestationApplicationId.get().signatureDigests) {
                addLog(indent + "\t" + Base64.toBase64String(digest));
            }
        }
    }

    private <T> void printOptional(Optional<T> optional, String caption) {
        if (optional.isPresent()) {
            if (optional.get() instanceof byte[]) {
                addLog(caption + ": " + Base64.toBase64String((byte[]) optional.get()));
            } else {
                addLog(caption + ": " + optional.get());
            }
        }
    }

    private static void verifyCertificateChain(X509Certificate[] certs)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException, IOException {
        X509Certificate parent = certs[certs.length - 1];
        for (int i = certs.length - 1; i >= 0; i--) {
            X509Certificate cert = certs[i];
            // Verify that the certificate has not expired.
            cert.checkValidity();
            cert.verify(parent.getPublicKey());
            parent = cert;
            try {
                CertificateRevocationStatus certStatus = CertificateRevocationStatus
                        .fetchStatus(cert.getSerialNumber());
                if (certStatus != null) {
                    throw new CertificateException(
                            "Certificate revocation status is " + certStatus.status.name());
                }
            } catch (IOException e) {
                throw new IOException("Unable to fetch certificate status. Check connectivity.");
            }
        }

        // If the attestation is trustworthy and the device ships with hardware-
        // level key attestation, Android 7.0 (API level 24) or higher, and
        // Google Play services, the root certificate should be signed with the
        // Google attestation root key.
        X509Certificate secureRoot =
                (X509Certificate)
                        CertificateFactory.getInstance("X.509")
                                .generateCertificate(
                                        new ByteArrayInputStream(GOOGLE_ROOT_CERTIFICATE.getBytes(UTF_8)));
        if (Arrays.equals(
                secureRoot.getPublicKey().getEncoded(),
                certs[certs.length - 1].getPublicKey().getEncoded())) {
            System.out.println(
                    "The root certificate is correct, so this attestation is trustworthy, as long as none of"
                            + " the certificates in the chain have been revoked. A production-level system"
                            + " should check the certificate revocation lists using the distribution points that"
                            + " are listed in the intermediate and root certificates.");
        } else {
            System.out.println(
                    "The root certificate is NOT correct. The attestation was probably generated by"
                            + " software, not in secure hardware. This means that, although the attestation"
                            + " contents are probably valid and correct, there is no proof that they are in fact"
                            + " correct. If you're using a production-level system, you should now treat the"
                            + " properties of this attestation certificate as advisory only, and you shouldn't"
                            + " rely on this attestation certificate to provide security guarantees.");
        }
    }

    public void importWrappedKey(KeyStore ks, String wrappingKeyAlias, byte[] wrappedKey) throws Exception {
        AlgorithmParameterSpec spec = new KeyGenParameterSpec.Builder(wrappingKeyAlias,
                KeyProperties.PURPOSE_WRAP_KEY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build();
        KeyStore.Entry wrappedKeyEntry = new WrappedKeyEntry(wrappedKey, wrappingKeyAlias,
                "RSA/ECB/OAEPPadding", spec);
        ks.setEntry(ALIAS, wrappedKeyEntry, null);
    }

    private KeyPair genKeyPair(String alias, byte[] challengeBytes) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        kpg.initialize(
                new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_WRAP_KEY)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                        .setIsStrongBoxBacked(hasStrongBox())
                        .setAttestationChallenge(challengeBytes)
                        .setKeySize(4096)
                        .build());
        return kpg.generateKeyPair();
    }

    // BE
    public byte[] wrapKey(PublicKey publicKey, byte[] keyMaterial, byte[] mask,
                          DERSequence authorizationList)
            throws Exception {

        // Build description
        DEREncodableVector descriptionItems = new DEREncodableVector();
        descriptionItems.add(new DERInteger(KM_KEY_FORMAT_RAW));
        descriptionItems.add(authorizationList);
        DERSequence wrappedKeyDescription = new DERSequence(descriptionItems);

        // Generate 12 byte initialization vector
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        addLog("iv::: ");
        addLog(bytesToHex(iv));
        System.out.println("iv >>>");
        System.out.println(bytesToHex(iv));

        // Generate 256 bit AES key. This is the ephemeral key.
        byte[] aesKeyBytes = new byte[32]; //32 original value
        random.nextBytes(aesKeyBytes);

        addLog("aesKeyBytes::: ");
        addLog(bytesToHex(aesKeyBytes));
        System.out.println("aesKeyBytes >>>");
        System.out.println(bytesToHex(aesKeyBytes));

        addLog("keyMaterial::: ");
        addLog(bytesToHex(keyMaterial));
        System.out.println("keyMaterial >>>");
        System.out.println(bytesToHex(keyMaterial));

        // Encrypt ephemeral keys
        // se encripta la clave que encriptara la clave efimera con la clave publica
        // paso opcional --> XOR con mask(clave de transito)
        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
        Cipher pkCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        pkCipher.init(Cipher.ENCRYPT_MODE, publicKey, spec);
        byte[] encryptedTransportKey = pkCipher.doFinal(aesKeyBytes);

        // Encrypt secure key / encryptedKey
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKeyBytes, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] aad = wrappedKeyDescription.getEncoded();
        cipher.updateAAD(aad); // Additional Authentication Data
        byte[] encryptedSecureKey = cipher.doFinal(keyMaterial);

        // Get GCM tag. Java puts the tag at the end of the ciphertext data :(
        int len = encryptedSecureKey.length;
        int tagSize = (GCM_TAG_SIZE / 8);
        byte[] tag = Arrays.copyOfRange(encryptedSecureKey, len - tagSize, len);

        addLog("tag::: ");
        addLog(bytesToHex(tag));
        System.out.println("tag >>>");
        System.out.println(bytesToHex(tag));

        // Remove GCM tag from end of output
        encryptedSecureKey = Arrays.copyOfRange(encryptedSecureKey, 0, len - tagSize);

        addLog("encryptedSecureKey::: ");
        addLog(bytesToHex(encryptedSecureKey));
        System.out.println("encryptedSecureKey >>>");
        System.out.println(bytesToHex(encryptedSecureKey));

        // Build ASN.1 DER encoded sequence WrappedKeyWrapper
        DEREncodableVector items = new DEREncodableVector();

        /**
         * version -> 0
         * */
        items.add(new DERInteger(WRAPPED_FORMAT_VERSION));

        /**
         * encryptedTransportKey es una clave AES de 256 bits,
         * XOR con una clave de enmascaramiento y luego cifrada
         * en modo RSA-OAEP (resumen SHA-256, resumen SHA-1 MGF1) con la clave de
         * encapsulado especificada por wrapperKeyBlob.
         * */
        items.add(new DEROctetString(encryptedTransportKey));

        /**
         * initializationVector
         * */
        items.add(new DEROctetString(iv));

        /**
         * KeyDescription ::= SEQUENCE(
         *          keyFormat INTEGER,                   # Values from KeyFormat enum.
         *          keyParams AuthorizationList,
         *      )
         * */
        items.add(wrappedKeyDescription);

        /**
         * encryptedKey
         * */
        items.add(new DEROctetString(encryptedSecureKey));

        /**
         * tag
         * */
        items.add(new DEROctetString(tag));

        return new DERSequence(items).getEncoded(ASN1Encoding.DER);
    }

    /**
     * xor of two byte[] for masking or unmasking transit keys
     */
    private byte[] xor(byte[] key, byte[] mask) {
        byte[] out = new byte[key.length];
        for (int i = 0; i < key.length; i++) {
            out[i] = (byte) (key[i] ^ mask[i]);
        }
        return out;
    }

    private DERSequence makeAuthList(int size,
                                     int algorithm_) {

        // Make an AuthorizationList to describe the secure key
        // https://developer.android.com/training/articles/security-key-attestation.html#verifying
        DEREncodableVector allPurposes = new DEREncodableVector();
        allPurposes.add(new DERInteger(KM_PURPOSE_ENCRYPT));
        allPurposes.add(new DERInteger(KM_PURPOSE_DECRYPT));
        DERSet purposeSet = new DERSet(allPurposes);
        DERTaggedObject purpose = new DERTaggedObject(true, 1, purposeSet);
        DERTaggedObject algorithm = new DERTaggedObject(true, 2, new DERInteger(algorithm_));
        DERTaggedObject keySize =
                new DERTaggedObject(true, 3, new DERInteger(size));
        DEREncodableVector allBlockModes = new DEREncodableVector();
        allBlockModes.add(new DERInteger(KM_MODE_ECB));
        allBlockModes.add(new DERInteger(KM_MODE_CBC));
        DERSet blockModeSet = new DERSet(allBlockModes);
        DERTaggedObject blockMode = new DERTaggedObject(true, 4, blockModeSet);
        DEREncodableVector allPaddings = new DEREncodableVector();
        allPaddings.add(new DERInteger(KM_PAD_PKCS7));
        allPaddings.add(new DERInteger(KM_PAD_NONE));
        DERSet paddingSet = new DERSet(allPaddings);
        DERTaggedObject padding = new DERTaggedObject(true, 6, paddingSet);
        DERTaggedObject noAuthRequired = new DERTaggedObject(true, 503, DERNull.INSTANCE);

        // Build sequence
        DEREncodableVector allItems = new DEREncodableVector();
        allItems.add(purpose);
        allItems.add(algorithm);
        allItems.add(keySize);
        allItems.add(blockMode);
        allItems.add(padding);
        allItems.add(noAuthRequired);
        return new DERSequence(allItems);
    }

    public static void runWBC(){
        WhiteBox wbc = new WhiteBox();

        SecureRandom random = new SecureRandom();
        byte ivOrNonce[] = new byte[15];
        random.nextBytes(ivOrNonce);
        String ivOrNonceHex = bytesToHex(ivOrNonce);
        System.out.println("WBC ivOrNonce --> " + ivOrNonceHex);

        // hello wbc world
        String plainTextHex = "68656c6c6f2077626320776f726c6420";

        byte[] cipher = wbc.encrypt(plainTextHex,ivOrNonceHex);
        String cipherHex = bytesToHex(cipher);
        System.out.println("WBC cipherHex --> " + cipherHex);

        byte[] plain = wbc.decrypt(cipherHex,ivOrNonceHex);
        String plainHex = bytesToHex(plain);
        System.out.println("WBC plainHex --> " + plainHex);
        System.out.println("WBC plain text --> " + hexToString(plainHex));
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String hexToString(String hex) {
        StringBuilder sb = new StringBuilder();
        char[] hexData = hex.toCharArray();
        for (int count = 0; count < hexData.length - 1; count += 2) {
            int firstDigit = Character.digit(hexData[count], 16);
            int lastDigit = Character.digit(hexData[count + 1], 16);
            int decimal = firstDigit * 16 + lastDigit;
            sb.append((char) decimal);
        }
        return sb.toString();
    }

    public static void generateECDH(){
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            keyPairGenerator.initialize(
                new KeyGenParameterSpec.Builder(
                        "eckeypair",
                        KeyProperties.PURPOSE_AGREE_KEY)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .build());
            KeyPair myKeyPair = keyPairGenerator.generateKeyPair();

            byte[] ourPk = myKeyPair.getPublic().getEncoded();
            System.out.println("getPublic len is " + ourPk.length);

            byte[] ourPrk = myKeyPair.getPrivate().getEncoded();
            System.out.println("getPrivate len is " + ourPrk.length);




            // Exchange public keys with server. A new ephemeral key MUST be used for every message.
            //PublicKey serverEphemeralPublicKey; // Ephemeral key received from server.

            // Create a shared secret based on our private key and the other party's public key.
            /*KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore");
            keyAgreement.init(myKeyPair.getPrivate());
            keyAgreement.doPhase(serverEphemeralPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            // sharedSecret cannot safely be used as a key yet. We must run it through a key derivation
            // function with some other data: "salt" and "info". Salt is an optional random value,
            // omitted in this example. It's good practice to include both public keys and any other
            // key negotiation data in info. Here we use the public keys and a label that indicates
            // messages encrypted with this key are coming from the server.
            byte[] salt = {};
            ByteArrayOutputStream info = new ByteArrayOutputStream();
            info.write("ECDH secp256r1 AES-256-GCM-SIV\0".getBytes(StandardCharsets.UTF_8));
            info.write(myKeyPair.getPublic().getEncoded());
            info.write(serverEphemeralPublicKey.getEncoded());

            // This example uses the Tink library and the HKDF key derivation function.
            AesGcmSiv key = new AesGcmSiv(Hkdf.computeHkdf(
                    "HMACSHA256", sharedSecret, salt, info.toByteArray(), 32));
            byte[] associatedData = {};
            return key.decrypt(ciphertext, associatedData);*/

        }catch (NoSuchProviderException e){
            System.out.println("myKeyPair error NoSuchProviderException --> " + e.toString());
        }catch (NoSuchAlgorithmException e){
            System.out.println("myKeyPair error NoSuchAlgorithmException --> " + e.toString());
        }catch (InvalidAlgorithmParameterException e){
            System.out.println("myKeyPair error InvalidAlgorithmParameterException --> " + e.toString());
        }/*catch (InvalidKeySpecException e) {
            // Not an Android KeyStore key.
        }/*catch (InvalidKeyException e){

        }catch (IOException e){

        }*/



    }

}