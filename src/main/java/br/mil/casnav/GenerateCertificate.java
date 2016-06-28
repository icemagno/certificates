package br.mil.casnav;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

public class GenerateCertificate {
	private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
			
	public static KeyPair generateRSAKeyPair() throws Exception {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", PROVIDER);
		kpGen.initialize(1024, new SecureRandom());
		return kpGen.generateKeyPair();
	}	


	public static ContentSigner createSigner(PrivateKey privateKey) {
	    try {
	        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSAEncryption");
	        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

	        return new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
	                .build(PrivateKeyFactory.createKey(privateKey.getEncoded()));
	    } catch (Exception e) {
	        throw new RuntimeException("Could not create content signer.", e);
	    }
	}

	public static void main(String[] args)  {
		
		Security.addProvider( new org.bouncycastle.jce.provider.BouncyCastleProvider() );
		
		try {
			
			KeyPair caKeyPair = generateRSAKeyPair();
			String subject = "magno";

			X500Name subjectDN = new X500Name("CN=" + subject);
			BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
			Date validityStartDate = new Date(System.currentTimeMillis() - 100000);
			Calendar calendar = Calendar.getInstance();
			calendar.add(Calendar.YEAR, 10);
			Date validityEndDate = new Date(calendar.getTime().getTime());
			SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded());

			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(subjectDN, serialNumber, validityStartDate,
					validityEndDate, subjectDN, subPubKeyInfo);
			
			X509CertificateHolder holder = builder.build( createSigner(caKeyPair.getPrivate()));

			X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
			
			File fil = new File( "d:/certs/mycert.cer" );
			FileOutputStream fos = new FileOutputStream(  fil );
			fos.write( cert.getEncoded() );
			fos.flush();
			fos.close();			
			
		} catch (Exception e) {
			e.printStackTrace();
		}		



	}

}
