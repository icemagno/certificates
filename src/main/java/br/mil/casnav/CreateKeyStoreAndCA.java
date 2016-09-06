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
	private static CreateKeyStoreAndCA ss;
	private static String certICPAlias;
	private static String keyStoreFileEmissor = "d:/certs/IPC-Brasil-Teste.jks";
	
	private static String keyStorePassword = "senha1234567890##123";
	private static String privateKeyPassword = "senha1234567890##123";	
	
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
    
    private void genAc( String certAlias, String keyStoreFile, String certificateFile, String storePassword, String privateKeyPassword, X500Name subjectName, X500Name issuerName ) {
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

    
    private void createUserCertAndSignWithAC(String acKeyAlias, String certAlias, String keyStoreFile, String fileName, String storePassword, String privateKeyPassword, X500Name subjectName, X500Name issuerName ) {
        String certificateFile = fileName + ".cer";
        String userKeystoreFile = fileName + ".jks";
        
        System.out.println("Gerando certificado para " + subjectName.toString() );
        
    	try {
        	char[] pkPassword = privateKeyPassword.toCharArray();
        	
        	KeyPair keyPair = generateKeyPair();
            PublicKey userPublicKey = keyPair.getPublic();
            PrivateKey userPrivateKey = keyPair.getPrivate();
            
            // Pega a chave privada de quem ASSINA o certificado ( emissor )
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load( getKeyStore( keyStoreFile ) , storePassword.toCharArray() );
            PrivateKey certSignerPrivateKey = (PrivateKey)ks.getKey(acKeyAlias, pkPassword );
            
            // Gera o certifiado do usuário e assina com a chave privada do emissor
            X509Certificate cert = createCert(issuerName, subjectName, certificateFile, userPublicKey, certSignerPrivateKey );
            X509Certificate[] outChain = { cert };
            
            // Algumas validações
            java.security.cert.Certificate caCert = ks.getCertificate( acKeyAlias );
            PublicKey certSignerPublicKey = caCert.getPublicKey();
            cert.checkValidity( new Date() );
            cert.verify( certSignerPublicKey );
            

            // Salva o novo certificado no chaveiro do emissor
            ks.setKeyEntry(certAlias, keyPair.getPrivate(), pkPassword, outChain);
            OutputStream writeStream = new FileOutputStream( keyStoreFile );
            ks.store( writeStream, storePassword.toCharArray() );
            writeStream.close();
            

            // Cria um chaveiro para o usuário com seu certificado
            KeyStore ksUser = KeyStore.getInstance("PKCS12");
            ksUser.load( null , storePassword.toCharArray() );
            ksUser.setKeyEntry(certAlias, userPrivateKey, pkPassword, outChain);
            OutputStream writeStreamUser = new FileOutputStream( userKeystoreFile );
            ksUser.store( writeStreamUser, storePassword.toCharArray() );
            writeStreamUser.close();            
            
            
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
        	
        	// Cria certificados e chaves da ICP Brasil (Teste)
        	String IPCBrasilCertificate = "d:/certs/IPC-Brasil-Teste.cer";
        	certICPAlias = "ICP.Brasil";
            X500Name icpBrasilIssuer = new X500Name("CN=TESTE Autoridade Certificadora Raiz Brasileira, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da Informacao - ITI, OU=CERTIFICADO DE TESTE,ST=TESTE CASNAV, C=BR");
			ss = new CreateKeyStoreAndCA();
			ss.genAc( certICPAlias, keyStoreFileEmissor, IPCBrasilCertificate, keyStorePassword, privateKeyPassword, icpBrasilIssuer, icpBrasilIssuer);
			
			
			// Cria Certificado AC Defesa
        	String acDefesaCertificate = "d:/certs/AC-Defesa-Teste";
        	String acDefesaAlias = "AC.Defesa";
            X500Name acDefesaIssuer = new X500Name("CN=TESTE Autoridade Certificadora Ministério da Defesa, O=AC-Defesa, OU=Ministério da Defesa, OU=CERTIFICADO DE TESTE, ST=TESTE CASNAV, C=BR");
			ss.createUserCertAndSignWithAC( certICPAlias, acDefesaAlias, keyStoreFileEmissor, acDefesaCertificate, keyStorePassword, privateKeyPassword, acDefesaIssuer, icpBrasilIssuer );

			// Cria Certificado AR Defesa
        	String arDefesaCertificate = "d:/certs/AR-Defesa-Teste";
        	String arDefesaAlias = "AR.Defesa";
            X500Name arDefesaIssuer = new X500Name("CN=TESTE Autoridade Registradora Ministério da Defesa, O=AR-Defesa, OU=Ministério da Defesa, OU=CERTIFICADO DE TESTE, ST=TESTE CASNAV, C=BR");
			ss.createUserCertAndSignWithAC( acDefesaAlias, arDefesaAlias, keyStoreFileEmissor, arDefesaCertificate, keyStorePassword, privateKeyPassword, arDefesaIssuer, acDefesaIssuer );
			
			// Gera certificado de usuário
			createUserCertDefesa(arDefesaAlias, "51984881787", "ALDECIR VIEIRA SIMONACI", arDefesaIssuer);
			createUserCertDefesa(arDefesaAlias, "16862043889", "Gleiton Farias de Souza", arDefesaIssuer);
			createUserCertDefesa(arDefesaAlias, "01231584785", "Eliseu Dias da Silva", arDefesaIssuer);
			createUserCertDefesa(arDefesaAlias, "01554862760", "Silvana do Valle Leone", arDefesaIssuer);
			createUserCertDefesa(arDefesaAlias, "02331751722", "Nacelio Alves Pessoa", arDefesaIssuer);
			
			/*
				51984881787 Aldecir Vieira Simonaci     aldecir.simonaci@defesa.gov.br  
				16862043889 Gleiton Farias de Souza     gleiton.souza@defesa.gov.br    
				01231584785 Eliseu Dias da Silva        eliseu.silva@defesa.gov.br        
				01554862760 Silvana do Valle Leone      silvana.leone@defesa.gov.br      
				02331751722 Nacelio Alves Pessoa        nacelio.pessoa@defesa.gov.br  			
			*/
			
			createUserCertCasnav(arDefesaAlias, "34747591753", "Edgard Candido de Oliveira Neto", arDefesaIssuer);
			createUserCertCasnav(arDefesaAlias, "00093406703", "Luciene Carvalho Correa de Souza", arDefesaIssuer);
			createUserCertCasnav(arDefesaAlias, "12021963730", "Priscilla Moreno", arDefesaIssuer);
			createUserCertCasnav(arDefesaAlias, "07946532865", "Sebastião Alves da Silva", arDefesaIssuer);
			createUserCertCasnav(arDefesaAlias, "12386616703", "Arthur Azevedo de Andrade", arDefesaIssuer);
			createUserCertCasnav(arDefesaAlias, "08097752719", "Jonathas Pacífico de Souza", arDefesaIssuer);
			createUserCertCasnav(arDefesaAlias, "97454915787", "Mauricio Figueiredo Cordeiro", arDefesaIssuer);
			createUserCertCasnav(arDefesaAlias, "02221224710", "Carlos Magno Oliveira de Abreu", arDefesaIssuer);
			/*
				34747591753 Edgard Candido de Oliveira Neto 	edgard@casnav.mar.mil.br        
				00093406703 Luciene Carvalho Correa de Souza 	luciene.carvalho@casnav.mar.mil.br
				12021963730 Priscilla Moreno                	priscila.moreno6@casnav.mil.mar.br    
				07946532865 Sebastião Alves da Silva        	alves@casnav.mil.mar.br
				12386616703 Arthur Azevedo de Andrade       	arthur.andrade@casnav.mar.mil.br
				08097752719 Jonathas Pacífico de Souza      	jonathas.souza@casnav.mar.mil.br
				97454915787 Mauricio Figueiredo Cordeiro 		mauricio.cordeiro@casnav.mar.mil.br
				02221224710 Carlos Magno Oliveira de Abreu		magno.abreu@casnav.mar.mil.br			
			*/
			
		} catch (Exception e) {
			e.printStackTrace();
		}		
	}

	private static void createUserCertDefesa( String emissorAlias, String cpf, String name, X500Name emissor) {
    	String certificateFile = "d:/certs/" + cpf;
    	String cn = name.toUpperCase() + ":" + cpf;
        X500Name requerente = new X500Name("CN="+cn+", O=Defesa, OU=Ministério da Defesa, ST=TESTE CASNAV, C=BR");
		ss.createUserCertAndSignWithAC( emissorAlias, cpf, keyStoreFileEmissor, certificateFile, keyStorePassword, privateKeyPassword, requerente, emissor );
	}

	private static void createUserCertCasnav( String emissorAlias, String cpf, String name, X500Name emissor) {
    	String certificateFile = "d:/certs/" + cpf;
    	String cn = name.toUpperCase() + ":" + cpf;
        X500Name requerente = new X500Name("CN="+cn+", O=CASNAV, OU=Marinha do Brasil, ST=TESTE CASNAV, C=BR");
		ss.createUserCertAndSignWithAC( emissorAlias, cpf, keyStoreFileEmissor, certificateFile, keyStorePassword, privateKeyPassword, requerente, emissor );
	}
	
	
}
