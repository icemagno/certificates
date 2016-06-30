package br.mil.casnav;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
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
import java.util.Calendar;
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

public class CreateKeyStoreAndCA {
	
    private static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    private static final String SIGNATURE_ALGORITHM = "SHA1WithRSA";
    private static final String KEY_GENERATION_ALGORITHM = "RSA";
    
    private InputStream  getKeyStore( String fileName  ) throws Exception {
    	File fil = new File(fileName );
    	if ( fil.exists() ) {
    		return new FileInputStream( fileName );
    	}
    	return null;
    }
    
    
    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( KEY_GENERATION_ALGORITHM, PROVIDER_NAME );
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        return keyPair;
    }
    
    private void genKeystore( String certAlias, String keyStoreFile, String certificateFile, String storePassword, String privateKeyPassword, X500Name subjectName, X500Name issuerName ) {
        try {
        	
        	char[] pkPassword = privateKeyPassword.toCharArray();
        	
        	KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            
            // Pega a chave privada de quem ASSINA o certificado ( O próprio )
            PrivateKey certSignerPrivateKey = keyPair.getPrivate();
            
            X509Certificate cert = createCert(issuerName, subjectName, certificateFile, publicKey, certSignerPrivateKey );
            X509Certificate[] outChain = { cert };
            
            KeyStore ks = KeyStore.getInstance("PKCS12");

            ks.load( null , storePassword.toCharArray() );
            ks.setKeyEntry(certAlias, certSignerPrivateKey, pkPassword, outChain);
            
            OutputStream writeStream = new FileOutputStream( keyStoreFile );
            ks.store( writeStream, storePassword.toCharArray() );
            writeStream.close();
            
            System.out.println("Server Public Cert Key: " + cert.getPublicKey());
            System.out.println("Server Public Key: " + keyPair.getPublic());
            System.out.println("Server Private Key: " + keyPair.getPrivate());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }	
    
    private static SubjectKeyIdentifier createSubjectKeyIdentifier(Key key) throws Exception {
        ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(key.getEncoded()));
        ASN1Sequence seq = (ASN1Sequence) is.readObject();
        is.close();
        @SuppressWarnings("deprecation")
        SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(seq);
        return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info);
    }
    
    
    private X509Certificate createCert(X500Name issuerName, X500Name subjectName, String certFilePath, PublicKey publicKey, PrivateKey certSignerPrivateKey ) throws Exception {
        BigInteger serial = BigInteger.valueOf(new SecureRandom().nextInt());
        
        
        Calendar calendar = Calendar.getInstance();
        Date today = calendar.getTime();
        Date BEFORE = today;
        calendar.add(Calendar.YEAR, 1);
        Date nextYear = calendar.getTime();
        Date AFTER = nextYear;
        
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

        X509Certificate cert = signCertificate(builder, certSignerPrivateKey);
        
		File fil = new File(certFilePath);
		FileOutputStream fos = new FileOutputStream( fil );
		fos.write( cert.getEncoded() );
		fos.flush();
		fos.close();	        
        
        return cert;
    }	
	
    private static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey signedWithPrivateKey) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME).build(signedWithPrivateKey);
        return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificateBuilder.build(signer));
    }    

    
    private void createUserCertAndSignWithAC(String acKeyAlias, String certAlias, String keyStoreFile, String certificateFile, String storePassword, String privateKeyPassword, X500Name subjectName, X500Name issuerName ) {
        try {
        	char[] pkPassword = privateKeyPassword.toCharArray();
        	
        	KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            
            // Pega a chave privada de quem ASSINA o certificado ( CA )
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load( getKeyStore( keyStoreFile ) , storePassword.toCharArray() );
            PrivateKey certSignerPrivateKey = (PrivateKey)ks.getKey(acKeyAlias, pkPassword );
            
            // Gera o certifiado do usuário e assina com a chave privada da AC
            X509Certificate cert = createCert(issuerName, subjectName, certificateFile, publicKey, certSignerPrivateKey );
            X509Certificate[] outChain = { cert };
            
            // Algumas validações
            java.security.cert.Certificate caCert = ks.getCertificate( acKeyAlias );
            PublicKey certSignerPublicKey = caCert.getPublicKey();
            cert.checkValidity( new Date() );
            cert.verify( certSignerPublicKey );
            

            // Salva o novo certificado no chaveiro
            ks.setKeyEntry(certAlias, keyPair.getPrivate(), pkPassword, outChain);
            OutputStream writeStream = new FileOutputStream( keyStoreFile );
            ks.store( writeStream, storePassword.toCharArray() );
            writeStream.close();
            
            System.out.println("User Public Cert Key: " + cert.getPublicKey());
            System.out.println("User Public Key: " + keyPair.getPublic());
            System.out.println("User Private Key: " + keyPair.getPrivate());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    	
    	
    	
    }
    
    
    
    
    
    
    /*
    country (countryName, C),
    organization (organizationName, O),
    organizational unit (organizationalUnitName, OU),
    distinguished name qualifier (dnQualifier),
    state or province name (stateOrProvinceName, ST),
    common name (commonName, CN) and
    serial number (serialNumber).
    */
	public static void main(String[] args)  {
		try {
			
        	String keyStoreFile = "d:/certs/keystore.jks";
        	String keyStorePassword = "senha1234567890##123";
        	String privateKeyPassword = "senha1234567890##123";
        	String caCertificate = "d:/certs/ac.cer";
        	String certACAlias = "Super.Vaca";
        	
            X500Name issuerName = new X500Name("CN=SuperVaca, O=CASNAV, OU=APOLO, ST=RJ, C=Brasil");
			
			CreateKeyStoreAndCA ss = new CreateKeyStoreAndCA();
			ss.genKeystore( certACAlias, keyStoreFile, caCertificate, keyStorePassword, privateKeyPassword, issuerName, issuerName);
			
        	String userCertificate = "d:/certs/user001.cer";
        	String certUserAlias = "User.001";
            X500Name subjectName = new X500Name("CN=Usuario01, O=CASNAV, OU=APOLO, ST=RJ, C=Brasil");
			ss.createUserCertAndSignWithAC( certACAlias, certUserAlias, keyStoreFile, userCertificate, keyStorePassword, privateKeyPassword, subjectName, issuerName );
			
		} catch (Exception e) {
			e.printStackTrace();
		}		
	}

}
