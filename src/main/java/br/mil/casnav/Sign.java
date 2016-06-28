package br.mil.casnav;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Sign {
	
    private byte[] nonce;
    private byte[] keyData;
	
    private static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    private static final String SIGNATURE_ALGORITHM = "SHA512withECDSA";
    private static final String KEY_GENERATION_ALGORITHM = "ECDH";
    private static final Date BEFORE = new Date(System.currentTimeMillis() - 5000);
    private static final Date AFTER = new Date(System.currentTimeMillis() + 600000);

    private void genNonce() {
        SecureRandom rand = new SecureRandom();
        this.nonce = new byte[2048];
        rand.nextBytes(nonce);
        return;
    }    
    
    private void genKeystore() {
        try {
        	
        	genNonce();
        	
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_GENERATION_ALGORITHM, PROVIDER_NAME);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            X509Certificate cert = createCACert(keyPair.getPublic(), keyPair.getPrivate());

            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null, (new String(this.nonce)).toCharArray());
            byte[] tempPass = new byte[2048];
            new SecureRandom().nextBytes(tempPass);
            ks.setKeyEntry("foo.bar", keyPair.getPrivate(), new String(tempPass).toCharArray(), new java.security.cert.Certificate[] { cert });
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            ks.store(os, (new String(this.nonce)).toCharArray());
            this.keyData = os.toByteArray();
            
            System.out.println("Server Key Data: " + new String(this.keyData));
            System.out.println("Server Public Cert Key: " + cert.getPublicKey());
            System.out.println("Server Public Key: " + keyPair.getPublic());
            System.out.println("Server Private Key: " + keyPair.getPrivate());
            
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return;
    }	
    
    private static SubjectKeyIdentifier createSubjectKeyIdentifier(Key key) throws Exception {
        ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(key.getEncoded()));
        ASN1Sequence seq = (ASN1Sequence) is.readObject();
        is.close();
        @SuppressWarnings("deprecation")
        SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(seq);
        return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info);
    }
	
    private X509Certificate createCACert(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        X500Name issuerName = new X500Name("CN=127.0.0.1, O=FOO, L=BAR, ST=BAZ, C=QUX");

        X500Name subjectName = issuerName;

        BigInteger serial = BigInteger.valueOf(new SecureRandom().nextInt());

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, BEFORE, AFTER, subjectName, publicKey);
        
        builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(publicKey));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.cRLSign);
        builder.addExtension(Extension.keyUsage, false, usage);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);
        builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

        X509Certificate cert = signCertificate(builder, privateKey);
        cert.checkValidity(new Date());
        cert.verify(publicKey);

        
		File fil = new File( "d:/certs/server.cer" );
		FileOutputStream fos = new FileOutputStream(  fil );
		fos.write( cert.getEncoded() );
		fos.flush();
		fos.close();	        
        
        return cert;
    }	
	
    private static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey signedWithPrivateKey) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME).build(signedWithPrivateKey);
        return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificateBuilder.build(signer));
    }    

	public static void main(String[] args)  {
		try {
			Sign ss = new Sign();
			ss.genKeystore();			
		} catch (Exception e) {
			e.printStackTrace();
		}		
	}

}
