package Utils;


import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import extendedEuclidAlgorithm.ExtendedEuclidAlgorithm;
import extendedEuclidAlgorithm.FastModularExponentitation;
/*
Person and Certification Authority classes extends this Common Class. 
Common attributes and functions have written in this class.
*/
public class Common {
	protected  BigInteger privateKey; 
	protected  BigInteger publicKey;
	protected BigInteger p;
	protected BigInteger g;
	protected  String name;
	
	
	public BigInteger getPrivateKey() {
		return privateKey;
	}
	public void setPrivateKey(BigInteger privateKey) {
		this.privateKey = privateKey;
	}
	public BigInteger getPublicKey() {
		return publicKey;
	}
	public void setPublicKey(BigInteger publicKey) {
		this.publicKey = publicKey;
	}
	public BigInteger getP() {
		return p;
	}
	public void setP(BigInteger p) {
		this.p = p;
	}
	public BigInteger getG() {
		return g;
	}
	public void setG(BigInteger g) {
		this.g = g;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	
	public BigInteger messageHashing(byte[] arr) throws NoSuchAlgorithmException {
		MessageDigest message = MessageDigest.getInstance("SHA-256");
		message.update(arr);
		BigInteger m = new BigInteger(1,message.digest());
		
		return m;
	}
	
	public static void writeCertificateFile(Certificate certificate, String fileName) throws IOException {
		File fout = new File(fileName);
		FileOutputStream fos = new FileOutputStream(fout);
	 
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos));
		
		bw.write(certificate.getCertificationAuthorityName());
		bw.newLine();
		bw.write(certificate.getIssuerName());
		bw.newLine();
		bw.write(certificate.getIssuerPublicKey());
		bw.newLine();
		bw.write(certificate.getDomainParameterP());
		bw.newLine();
		bw.write(certificate.getDomainParameterQ());
		bw.newLine();
		bw.write(certificate.getS1());
		bw.newLine();
		bw.write(certificate.getS2());
		bw.close();
		
		
	}
	
	public ArrayList<BigInteger> elGamalSignature(BigInteger messageHashing) {
		
		BigInteger k = generateK();
		
		BigInteger s1 = FastModularExponentitation.fastModExp(this.g, k, this.p);
		BigInteger inverseOfK = ExtendedEuclidAlgorithm.multiplicativeInverse(k, this.p.subtract(BigInteger.ONE));
		BigInteger s2 = inverseOfK.multiply(messageHashing.subtract(getPrivateKey().multiply(s1))).mod(this.p.subtract(BigInteger.ONE));
		ArrayList<BigInteger> signs = new ArrayList<>();
		signs.add(s1);
		signs.add(s2);
		return signs;
	}
	
	public ArrayList<BigInteger> elGamalVerification(BigInteger m, BigInteger s1, BigInteger s2, BigInteger publicKey ) {
		
		ArrayList<BigInteger> result = new ArrayList<>();
		
		BigInteger v1 = FastModularExponentitation.fastModExp(this.g, m , this.p);
		BigInteger v2  =(FastModularExponentitation.fastModExp(publicKey, s1 , this.p)).multiply(FastModularExponentitation.fastModExp(s1, s2, this.p)).mod(p);
		result.add(v1);
		result.add(v2);
		return result;
		
	}
	
	public ArrayList<String> readFileIntoArrayList(String certificateName) throws FileNotFoundException{
		File fileName = new File(certificateName);
		Scanner s = new Scanner(fileName);
		ArrayList<String> list = new ArrayList<String>();
		while (s.hasNext()){
		    list.add(s.next());
		}
		s.close();
		if(certificateName == "temp.txt")
			fileName.delete();
		return list;
	}
	
	  // This function generates random private key for users. 1<privateKey<p-1
	protected BigInteger generatePrivateKey() throws InterruptedException {
        BigInteger randomPrivate = new BigInteger(128, new Random());
        while (randomPrivate.compareTo(p.subtract(BigInteger.ONE)) == 1){
            randomPrivate = new BigInteger(128, new Random());
        }
        TimeUnit.SECONDS.sleep(1);
        return randomPrivate;
    }
	
	private BigInteger generateK() {
		BigInteger k = new BigInteger(128, new Random());
        while(k.compareTo(p.subtract(BigInteger.ONE)) == 1 || ExtendedEuclidAlgorithm.gcd(k,p.subtract(BigInteger.ONE)).compareTo(BigInteger.ONE) != 0){
            k = new BigInteger(128, new Random());
        }
        return k;
	}
	
	
	
	
	
	
}
