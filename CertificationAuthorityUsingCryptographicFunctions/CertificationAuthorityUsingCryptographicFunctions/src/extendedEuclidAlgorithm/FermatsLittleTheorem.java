package extendedEuclidAlgorithm;

import java.math.BigInteger;
import java.util.Random;

public class FermatsLittleTheorem {
	private static Random rand = new Random();
	private static BigInteger one = BigInteger.ONE;
	
	//function to check primality of a number using Fermat's little theorem
	public static boolean isPrime(BigInteger n) {
		BigInteger a = new BigInteger(n.bitLength(), rand);
		boolean primeFlag = false;
		int i = 0;
		while(a.compareTo(n) >= 0 && i < 1000) {
			a = new BigInteger(n.bitLength(), rand);
			if(ExtendedEuclidAlgorithm.gcd(a, n).intValue() > 1)
				primeFlag=false;
			
			if((a.modPow(n.subtract(one), n)).compareTo(one) == 0)
				primeFlag=true;
		}
			
		

		return primeFlag;	
	}
}