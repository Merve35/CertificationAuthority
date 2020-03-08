package Utils;


import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

import extendedEuclidAlgorithm.FastModularExponentitation;

public class CertificationAuthority extends Common {
	
	
	public CertificationAuthority(String certificationAuthorityName, BigInteger p, BigInteger g) throws InterruptedException {
		super();
		this.name = certificationAuthorityName;
		this.p = p;
		this.g = g;
		this.privateKey = generatePrivateKey();
		System.out.println(name + " Private Key : " + privateKey);
		TimeUnit.SECONDS.sleep(1);
		this.publicKey = generatePublicKey();
		System.out.println(name + " Public Key : " + publicKey);
		TimeUnit.SECONDS.sleep(1);
		
	}
	

	private BigInteger generatePublicKey() {
		return FastModularExponentitation.fastModExp(this.g, this.privateKey, this.p);	
	}
	
	
	public Certificate generateCertificate(String personName, BigInteger personPublicKey) throws IOException, NoSuchAlgorithmException {
		
		Certificate certificate = new Certificate(this.getName(), personName, personPublicKey.toString(), this.p.toString(), this.g.toString(),"","");
		writeCertificateFile(certificate, "Certificate_" + personName + ".txt");
		
		ArrayList<String> list = readFileIntoArrayList("Certificate_" + personName + ".txt");
	
		String str = list.toString();
		byte[] result = str.getBytes();
		
		//Convert arraylist into byte array;
		BigInteger m = this.messageHashing(result);
		
		ArrayList<BigInteger> signs = elGamalSignature(m);

		certificate.setS1(signs.get(0).toString());
		certificate.setS2(signs.get(1).toString());
		
		writeCertificateFile(certificate, "Certificate_" + personName + ".txt");
		return certificate;
		
	}
	
	
	
	
	
	
	
	
}
