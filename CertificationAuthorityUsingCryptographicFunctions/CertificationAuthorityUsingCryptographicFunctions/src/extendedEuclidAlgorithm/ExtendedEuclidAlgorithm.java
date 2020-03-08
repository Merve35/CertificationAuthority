package extendedEuclidAlgorithm;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class ExtendedEuclidAlgorithm {
	private static BigInteger one = BigInteger.ONE;
	private static BigInteger zero = BigInteger.ZERO;
	
	//function for only returns gcd of two numbers
	public static BigInteger gcd(BigInteger a, BigInteger b) {
		
		if(a.compareTo(zero) == 0 ) 
			return b;	

		BigInteger gcd = gcd(b.mod(a),a);
		
		return gcd;
		
	}
	
	// find multiplicative inverse using extended euclid algorithm function
	public static BigInteger multiplicativeInverse(BigInteger a, BigInteger p) {
		if(a.compareTo(p) == 1) {
			BigInteger tmp  = a;
			a = p;
			p = tmp;
		}
		List<BigInteger> g = gcdExtended(a, p);
		BigInteger gcd = g.get(0);
		BigInteger x = g.get(1);
	
		if(!gcd.equals(one)) {
			System.out.println("Inverse does not exists");
			return zero;
		}
	
		return (x.mod(p).add(p)).mod(p);
		
	}
	
	//function for finding if two number are relatively prime or not
	public static boolean isRelativelyPrime(BigInteger a, BigInteger b) {
		return gcd(a,b).equals(one);
	}

	
	//find for gcd,x and y
	private static BigInteger u, v, q, r,temp;
	public static List<BigInteger> gcdExtended(BigInteger a, BigInteger b) {
	BigInteger x0 = BigInteger.ZERO, y0 = BigInteger.ONE, x1 = BigInteger.ONE, y1 = BigInteger.ZERO;
	if(a.equals(zero))
		throw new IllegalArgumentException("Error");
		
	if(a.compareTo(b) == 1) {
		BigInteger tmp  = a;
		a = b;
		b = tmp;
	}
		u = a; 
		v = b;
		while(u.compareTo(zero) != 0) {
			 q = v.divide(u);
			 r = v.mod(u);
			 v=u;
			 u=r;

			temp=x0;
			x0=x1.subtract(q.multiply(x0));
			x1=temp;
			
			temp=y0;
			y0=y1.subtract(q.multiply(y0));
			y1=temp;
		
		}

	
		List<BigInteger> gcd = new ArrayList<BigInteger>();
		gcd.add(v);
		gcd.add(y1);
		gcd.add(x1);
		return gcd;
	}
}
