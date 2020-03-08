package Utils;

import java.math.BigInteger;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import extendedEuclidAlgorithm.FermatsLittleTheorem;

public class PGGenerator {

    public static BigInteger generateP() throws InterruptedException {
        //This generate max 128 bit length random BigInteger.
        BigInteger randomP = new BigInteger(128, new Random());
        // If the generated random BigInteger is not prime, continue to generate.
        //checking primality using Fermat's little theorem.
        while(!FermatsLittleTheorem.isPrime(randomP)){
            randomP = new BigInteger(128, new Random());
        }
        System.out.println("Random P is generated: " + randomP);
        TimeUnit.SECONDS.sleep(1);
        return randomP;
    }

    //This generates g.
    public static BigInteger generateG(BigInteger p) throws InterruptedException {
        BigInteger randomG = new BigInteger(128, new Random());
        while(randomG.compareTo(p.subtract(BigInteger.ONE)) == 1){
            randomG = new BigInteger(128, new Random());
        }
        System.out.println("Random G is generated: " + randomG);
        TimeUnit.SECONDS.sleep(1);
        return randomG;
    }


}
