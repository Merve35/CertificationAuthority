package Utils;



import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

import extendedEuclidAlgorithm.AES;
import extendedEuclidAlgorithm.FastModularExponentitation;

public class Person extends Common {
	
	private BigInteger certificationAuthorityPublicKey;
	private BigInteger commonSharedSecretKey;
	private Certificate certificate;
	private Certificate othersCertificate;
	private ArrayList<BigInteger> signs; // others certificate signs
	private String message;
	private String receivedMessage;
	
	
	public Person(String name,BigInteger p, BigInteger g) throws InterruptedException {
		this.name = name;
		this.p=p;
		this.g=g;
		this.privateKey = generatePrivateKey(); //generatePrivateKey();
		System.out.println(name + " Private Key : " + privateKey);
		TimeUnit.SECONDS.sleep(1);
		this.publicKey = generatePublicKey();
		System.out.println(name + " Public Key : " + publicKey);
		TimeUnit.SECONDS.sleep(1);

	}

	

	public BigInteger getCertificationAuthorityPublicKey() {
		return certificationAuthorityPublicKey;
	}
	
	public String getReceivedMessage() {
		return receivedMessage;
	}

	public void setReceivedMessage(String receivedMessage) {
		this.receivedMessage = receivedMessage;
	}



	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}



	public Certificate getOthersCertificate() {
		return othersCertificate;
	}



	public void setOthersCertificateAndSigns(Certificate othersCertificate, ArrayList<BigInteger> signs) {
		this.othersCertificate = othersCertificate;
		this.signs = signs;
	}



	public Certificate getCertificate() {
		return certificate;
	}



	public void setCertificate(Certificate certificateName) {
		this.certificate = certificateName;
	}



	public void setCertificationAuthorityPublicKey(BigInteger certificationAuthorityPublicKey) {
		this.certificationAuthorityPublicKey = certificationAuthorityPublicKey;
	}


	public BigInteger getCommonSharedSecretKey() {
		return commonSharedSecretKey;
	}


	public void setCommonSharedSecretKey(BigInteger commonSharedSecretKey) {
		this.commonSharedSecretKey = commonSharedSecretKey;
	}


	public BigInteger generateCommonSharedSecretDHKE(BigInteger otherPublicKey){
		this.commonSharedSecretKey = FastModularExponentitation.fastModExp(otherPublicKey, this.privateKey, this.p);
			return commonSharedSecretKey;
	}



	private BigInteger generatePublicKey() {
		return FastModularExponentitation.fastModExp(this.g, this.privateKey, this.p);
		
	}
	
	
    //Person verifies Certification Authority
    public boolean verifyCertificationAuthority() throws IOException, NoSuchAlgorithmException {
    	String certificateName = (getName() + "Certificate.txt").toUpperCase();
		writeCertificateFile(this.certificate,certificateName);
		
		ArrayList<String> list = readFileIntoArrayList(certificateName); // read file into an arraylist
		
		BigInteger s2 = new BigInteger(list.get(list.size() - 1)); // getting sign 2 from arraylist
		list.remove(list.size()-1);
		
		BigInteger s1 = new BigInteger(list.get(list.size() - 1)); // getting sign 1 from arraylist
		list.remove(list.size()-1);	
		
		String str = list.toString(); // changing list into string
		byte[] result = str.getBytes(); // change string to byte array in order to hashing
		
		
        BigInteger m = this.messageHashing(result); // message is hashed.
        
		// compareList contains v1 and v2.
		ArrayList<BigInteger> compareList = elGamalVerification(m, s1, s2, certificationAuthorityPublicKey); 

		return compareList.get(0).compareTo(compareList.get(1)) == 0;
		
	}
    

    // Alice and Bob use this function to verify each other's certificate
    public boolean verifySignature(String certificateName) throws IOException, NoSuchAlgorithmException {
		// list contains lines from file
		ArrayList<String> list = readFileIntoArrayList(certificateName);
		
		BigInteger s2 = new BigInteger(list.get(list.size() - 1)); // getting sign 2 from arraylist
		list.remove(list.size()-1);
		
		BigInteger s1 = new BigInteger(list.get(list.size() - 1)); // getting sign 1 from arraylist
		list.remove(list.size()-1);
		
		String str = list.toString(); // arraylist changed into string
		byte[] result = str.getBytes(); // result contains bytes of str
        BigInteger m = this.messageHashing(result); // message is hashed.
        
		//signs contains v1 and v2
		ArrayList<BigInteger> signs = elGamalVerification(m, s1, s2, new BigInteger(list.get(2)));

		return signs.get(0).compareTo(signs.get(1)) == 0;
		
	}
    
    //Alice and Bob use this function to sign their certificates
    public ArrayList<BigInteger> signOwnCertificate(Certificate certificate) throws IOException, NoSuchAlgorithmException{
    	String fileName = "temp.txt"; // certificate is written to a file.
    	writeCertificateFile(certificate, fileName);
    	ArrayList<String> lines = readFileIntoArrayList(fileName); // read all lines in file and assigned into arraylist
    	
		String str = lines.toString(); // arraylist is translated to string
		byte[] result = str.getBytes(); // result contains bytes of string
    	BigInteger m = this.messageHashing(result); // message is hashed
    	ArrayList<BigInteger> signs = elGamalSignature(m); // signs contains s1 and s2
    	
    	return signs;
    }



	public boolean verifyTheOthersSignature() throws IOException, NoSuchAlgorithmException {
		String fileName = "temp.txt";  // certificate is written to a file.
		writeCertificateFile(othersCertificate, fileName);
		ArrayList<String> lines = readFileIntoArrayList(fileName); // read all lines in file and assigned into arraylist
		
		String str = lines.toString();// arraylist is translated to string
		byte[] result = str.getBytes();// result contains bytes of string
		BigInteger m = this.messageHashing(result);  // message is hashed
		ArrayList<BigInteger> compareList = elGamalVerification(m, this.signs.get(0), this.signs.get(1), new BigInteger(lines.get(3)));
		//compareList contains v1 and v2
		 return compareList.get(0).compareTo(compareList.get(1)) == 0;
	}
	
	public ArrayList<BigInteger> signMessage() throws NoSuchAlgorithmException{
		byte[] result = message.getBytes(); // string message is translated byte array.
		BigInteger m = this.messageHashing(result); // message is hashed.
		ArrayList<BigInteger> signs = elGamalSignature(m); // signatures are created.
		return signs;
	}
	
	public String concatenateMessageWithSigns(ArrayList<BigInteger> signs) {
		return message + "-" + signs.get(0).toString() + "-" + signs.get(1).toString(); // message and signs concatenated.
	}
	
	public String generateEncryptepMessage(String concatenatedMessage) {
		//Message is encrypted with common shared secret key
		return AES.encrypt(concatenatedMessage, this.commonSharedSecretKey.toString()); 
	}
    
	public String decryptReceivedMessage() {
		//Message is decrypted common shared secret key
		return AES.decrypt(receivedMessage, this.commonSharedSecretKey.toString());
	}
	
	public ArrayList<String> parseReceivedMessage(String message){
		//message is parsed with "-"
		String[] parsedMessage = message.split("-"); 
		ArrayList<String> parsed = new ArrayList<>();
		parsed.add(parsedMessage[0]); // contains mesage
		parsed.add(parsedMessage[1]); // s1
		parsed.add(parsedMessage[2]); // s2
		
		return parsed;
	}
	
	public boolean verifyReceivedMessage(ArrayList<String> mess) throws NoSuchAlgorithmException {
		byte[] result = mess.get(0).getBytes(); // message is translated to byte array
		BigInteger m = this.messageHashing(result); // message is hashed.
		
		//compareList contains v1 and v2. Message is verified.
		ArrayList<BigInteger> compareList = elGamalVerification(m,new BigInteger(mess.get(1)), new BigInteger(mess.get(2)), new BigInteger(othersCertificate.getIssuerPublicKey()));
	
		return compareList.get(0).compareTo(compareList.get(1)) == 0;
	}
	
	//This function sends the message from Alice to Bob
	public void sendMessage(Person person) throws NoSuchAlgorithmException, InterruptedException {

		ArrayList<BigInteger> signs = signMessage(); // signs are created.
		System.out.println("Message is signed..." + signs);
		TimeUnit.SECONDS.sleep(1);
		String concatenatedMessageWithSign = concatenateMessageWithSigns(signs); // message and signs are concatenated
		System.out.println("Message is concatenated with signs..." + concatenatedMessageWithSign);
		TimeUnit.SECONDS.sleep(1);
		String encrtyptedMessage = generateEncryptepMessage(concatenatedMessageWithSign); // encrypted message is created
		System.out.println("Message is encrypted with commonSharedSecretKey..." + encrtyptedMessage);
		TimeUnit.SECONDS.sleep(1);
		person.setReceivedMessage(encrtyptedMessage); // message is sended to Bob.
		System.out.println("Encrypted Message is send... :" );
		
	}
	
	public String decryptMessage() throws InterruptedException, NoSuchAlgorithmException {
		String decryptedMessage = decryptReceivedMessage(); // received message is decrypted.
		System.out.println("Message is decrypted... : " + decryptedMessage);
		TimeUnit.SECONDS.sleep(1);
		
		ArrayList<String> parsedReceivedMessage = parseReceivedMessage(decryptedMessage); // message + s1 + s2
		System.out.println("Message is parsed into message and signs..." + parsedReceivedMessage);
		TimeUnit.SECONDS.sleep(1);
		
		String message = parsedReceivedMessage.get(0); // message is created.
		boolean flag = verifyReceivedMessage(parsedReceivedMessage); // if value of flag is true, message is verified. Else not verified.
		System.out.println("Message is verifying..." + flag);
		TimeUnit.SECONDS.sleep(1);
		
		if(flag)
			return message;
		return null;
	}
   
	

	
	
}
