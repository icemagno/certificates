package br.mil.casnav;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;


public class Sign {
    static final String KEYSTORE_FILE = "d:/certs/keystore.jks";
    static final String KEYSTORE_INSTANCE = "PKCS12";
    static final String KEYSTORE_PWD = "senha1234567890##123";
    static final String KEYSTORE_ALIAS = "User.001";	

    // http://stackoverflow.com/questions/16662408/correct-way-to-sign-and-verify-signature-using-bouncycastle
    
    public static void verify( String envelopedData ) throws Exception {
        Security.addProvider( new BouncyCastleProvider() );

        CMSSignedData cms = new CMSSignedData(  Base64.decode(  envelopedData.getBytes()  )  );
        Store<?> store = cms.getCertificates(); 
        SignerInformationStore signers = cms.getSignerInfos(); 

        
        
        byte[] content = (byte[])cms.getSignedContent().getContent();
      	//String signedContent = new String( Base64.encode( (byte[]) cms.getSignedContent().getContent() ) , "UTF-8");        	
        System.out.println( new String( content ) );
            
                
        
        Collection<SignerInformation> c = signers.getSigners(); 
        Iterator<SignerInformation> it = c.iterator();
        while (it.hasNext()) { 
            SignerInformation signer = (SignerInformation) it.next(); 
			Collection certCollection = store.getMatches( signer.getSID() ); 
            Iterator certIt = certCollection.iterator();
            X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
            
            System.out.println( cert.getSubjectDN() );
            
            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                System.out.println("verified");
            }
        }
    	
    }
    

    public static String sign() throws Exception {
        String text = "This is a message";
        Security.addProvider( new BouncyCastleProvider() );
        
        KeyStore ks = KeyStore.getInstance(KEYSTORE_INSTANCE);
        ks.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PWD.toCharArray());
        Key key = ks.getKey(KEYSTORE_ALIAS, KEYSTORE_PWD.toCharArray());		
		
        //Sign
        PrivateKey privKey = (PrivateKey) key;
        Signature signature = Signature.getInstance("SHA1WithRSA", "BC");
        signature.initSign(privKey);
        signature.update(text.getBytes());

        //Build CMS
        X509Certificate cert = (X509Certificate) ks.getCertificate(KEYSTORE_ALIAS);
        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        
        CMSTypedData msg = new CMSProcessableByteArray(signature.sign());
        certList.add(cert);
        
        Store<?> certs = new JcaCertStore(certList);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey);
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, cert));
        gen.addCertificates(certs);
        
        
        CMSSignedData sigData = gen.generate(msg, true);

        String signedContent = new String( Base64.encode( (byte[]) sigData.getSignedContent().getContent() ) , "UTF-8"); 
        System.out.println("Signed content: " + signedContent + "\n");

        String envelopedData = new String(  Base64.encode(sigData.getEncoded()) , "UTF-8");
        System.out.println("Enveloped data: " + envelopedData );	
        
        return envelopedData;
    	
    }
    
   
	public static void main(String[] args) throws Exception {
		
		String data = sign();
		verify( data );

	}

}
