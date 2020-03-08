package extendedEuclidAlgorithm;

import java.math.BigInteger;

public class FastModularExponentitation {
	
	// x^y mod p
	private static BigInteger one = BigInteger.ONE;
	private static BigInteger zero = BigInteger.ZERO;
	
	public static BigInteger fastModExp(BigInteger x, BigInteger y, BigInteger p) {
		BigInteger result = BigInteger.ONE;
		
		x = x.mod(p);
		
		while(y.compareTo(zero) == 1) {
			BigInteger lsb = y.mod(BigInteger.valueOf(2));
			y = y.divide(BigInteger.valueOf(2));
			
			if(lsb.compareTo(one) == 0) {
				result = result.multiply(x);
				result = result.mod(p);
			}
			
			x = x.multiply(x);
			x = x.mod(p);
		}
		return result;
	}
}
