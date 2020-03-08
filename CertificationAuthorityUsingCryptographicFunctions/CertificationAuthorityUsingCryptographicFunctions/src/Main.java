import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import Utils.CertificationAuthority;
import Utils.PGGenerator;
import Utils.Person;



public class Main {

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InterruptedException {
		
		BigInteger P = PGGenerator.generateP();
		BigInteger G = PGGenerator.generateG(P);
		
		Person Alice = new Person("Alice", P, G);

		System.out.println("Alice is created...");
		TimeUnit.SECONDS.sleep(1);

		Person Bob = new Person("Bob", P, G);
		System.out.println("Bob is created...");
		TimeUnit.SECONDS.sleep(1);

		CertificationAuthority CA = new CertificationAuthority("Certification Authority", P, G);
		System.out.println("Certification Authority is created...");
		TimeUnit.SECONDS.sleep(1);
		
		Alice.setCertificationAuthorityPublicKey(CA.getPublicKey());
		Bob.setCertificationAuthorityPublicKey(CA.getPublicKey());
		
		Alice.setCertificate(CA.generateCertificate(Alice.getName(), Alice.getPublicKey()));
		System.out.println("Certificate of Alice is created and sended...");
		TimeUnit.SECONDS.sleep(1);
		
		
		Bob.setCertificate(CA.generateCertificate(Bob.getName(), Bob.getPublicKey()));
		System.out.println("Certificate of Bob is created and sended...");
		TimeUnit.SECONDS.sleep(1);
		
		
		System.out.println("Alice is verifying CA's signature = " + Alice.verifyCertificationAuthority());
		TimeUnit.SECONDS.sleep(1);
		
		System.out.println("Bob is verifying CA's signature = " + Bob.verifyCertificationAuthority());
		TimeUnit.SECONDS.sleep(1);
		
		Alice.setOthersCertificateAndSigns(Bob.getCertificate(), Bob.signOwnCertificate(Bob.getCertificate()));
		System.out.println("Alice is sending her certificate and signs to Bob...");
		TimeUnit.SECONDS.sleep(1);
		
		Bob.setOthersCertificateAndSigns(Alice.getCertificate(), Alice.signOwnCertificate(Alice.getCertificate()));
		System.out.println("Bob is sending his certificate and signs to Alice...");
		TimeUnit.SECONDS.sleep(1);
		
		System.out.println("Alice is verifying Bob's Signature = " + Alice.verifyTheOthersSignature());
		TimeUnit.SECONDS.sleep(1);
		
		System.out.println("Bob is verifying Alice's Signature = " + Bob.verifyTheOthersSignature());
		TimeUnit.SECONDS.sleep(1);
		
		Alice.setCommonSharedSecretKey(Alice.generateCommonSharedSecretDHKE(new BigInteger((Alice.getOthersCertificate().getIssuerPublicKey()))));
		System.out.println("Alice is generating common shared secret key using Bob's public key..." + Alice.getCommonSharedSecretKey());
		TimeUnit.SECONDS.sleep(1);
		
		Bob.setCommonSharedSecretKey(Bob.generateCommonSharedSecretDHKE(new BigInteger((Bob.getOthersCertificate().getIssuerPublicKey()))));
		System.out.println("Bob is generating common shared secret key using Alice's public key..." + Bob.getCommonSharedSecretKey());
		TimeUnit.SECONDS.sleep(1);
		
		String message = "Merve Bozoglu";
		
		Alice.setMessage(message);
		System.out.println("Alice preparing message...");
		TimeUnit.SECONDS.sleep(1);
		
		Alice.sendMessage(Bob);
		System.out.println("Alice sends message to Bob.");
		TimeUnit.SECONDS.sleep(1);
		
		
		System.out.println("Received message from Alice : " + Bob.decryptMessage());
		TimeUnit.SECONDS.sleep(1);
		

	}
		

		
		
	




}
