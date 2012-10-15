import java.security.SecureRandom;
import java.math.BigInteger;

public class RSA {
	
	static boolean DEBUG = true;
	
	BigInteger[] extended_gcd(BigInteger a, BigInteger b) {
		BigInteger x = BigInteger.ZERO;
		BigInteger y = BigInteger.ONE;
		BigInteger lastx = BigInteger.ONE;
		BigInteger lasty = BigInteger.ZERO;
		
		while (b.compareTo(BigInteger.ZERO) != 0) {
			BigInteger[] rl = a.divideAndRemainder(b);
			BigInteger quotient = rl[0];
			BigInteger r = rl[1];
			a = b; b = r;
			BigInteger tmp = lastx.subtract(quotient.multiply(x));
			x = tmp; lastx = x;
			tmp = lasty.subtract(quotient.multiply(y));
			y = tmp; lasty = x;
		}
		
		BigInteger[] rl = {lastx, lasty};
		return rl;
		
	}
	
	BigInteger[] createpq(int bitlen) {
		BigInteger p = createBigPrimeNumber(bitlen);
		BigInteger q; 
		while   ((q = createBigPrimeNumber(bitlen)).compareTo(p) == 0) ;
		
		BigInteger[] rl = {p, q};
		return rl;
		
	}
	
	BigInteger gcd(BigInteger a, BigInteger b) {
		BigInteger[] rl = extended_gcd(a, b);
		return a.multiply(rl[0]).add(b.multiply(rl[1]));
	}
	
	BigInteger finde(BigInteger p, BigInteger q) {
		BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		BigInteger e = createBigNumber(phi.bitLength()).mod(phi);
		while (gcd(e, phi).compareTo(BigInteger.ONE) != 0) {
			e = e.add(BigInteger.ONE).mod(phi);
		}
		
		if (e.bitLength() < 2)
			return finde(p, q);

		return e;
	}
	
	BigInteger encrypt(BigInteger m, BigInteger e, BigInteger n) {
		return powmod(m, e, n);
	}
	
	BigInteger findd(BigInteger e, BigInteger p, BigInteger q) {
		BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		BigInteger[] rl = extended_gcd(e, phi);
		
		return rl[0].add(phi).mod(phi);
	}
	
	/*
	 * Return a^d mod n
	 * 
	 */
	BigInteger powmod(BigInteger a, BigInteger d, BigInteger n) {
		int i;
		BigInteger rl = BigInteger.ONE;
		
		for (i = d.bitLength()-1; i >= 0; i--) {
			rl = rl.multiply(rl).mod(n);
			if (d.testBit(i)) rl = rl.multiply(a).mod(n);
		}
		
		return rl;
		
	}
	
	
	/*
	 * This method return a random number sized bitlen
	 * 
	 */
	BigInteger createBigNumber(int bitlen) {
		BigInteger num = BigInteger.ZERO;
		SecureRandom random = new SecureRandom();
		
		int i;
		
		// This loop creates a bitlen-bits number
		for (i = 0; i < bitlen-1; i++) {
			//num = num.multiply(BigInteger.valueOf(2));
			if (random.nextBoolean() == true) num = num.setBit(i);
		}
		
		num = num.setBit(bitlen - 1);

		return num;
	
	}
	
	
	/*
	 * This method implements Miller-Rabin primality test
	 * Reference algorithm at http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test 
	 * 
	 * Input:
	 * 		BigInteger n:	number we want check
	 * 		int		   k  :	the accuracy of the test	
	 * 
	 * Note: This algorithm run in O(k*lg^3(n)) time
	 * TODO: We need a faster algorithm! 
	 * 		+ Hint: We can use BitSieve ;)
	 * 				or FFT ?
	 */
	boolean isPrime(BigInteger n, int k) {
		int i;
		
		// n - 1= 2^s x d, s.t: d is odd number
		int s = 0;
		BigInteger d = n.subtract(BigInteger.ONE);
		BigInteger np1 = n.subtract(BigInteger.ONE);
		BigInteger TWO = BigInteger.valueOf(2);
		while (d.mod(TWO).compareTo(BigInteger.ZERO) == 0) {
			s++;
			d = d.divide(TWO);
		}
		
		// repeat k times
		for (i = 1; i <= k; i++) {
			BigInteger a = createBigNumber(n.bitLength()).mod(np1);

			// a must be in the range [2, n-2]
			if (!(a.compareTo(BigInteger.ONE)  == 1))
				a.add(TWO);
			
			BigInteger x = powmod(a, d, n);
			if (x.compareTo(BigInteger.ONE) == 0 || x.compareTo(np1) == 0) continue;
			int r;
			boolean flag = false;
			for (r = 1; r <= s; r++) {
				x = x.multiply(x).mod(n);
				if (x.compareTo(BigInteger.ONE) == 0)
					return false;
				if (x.compareTo(np1) == 0) {flag = true; break;}
			}
			if (!flag) return false;
			
		}
		
		return true;
	}
	
	BigInteger createBigPrimeNumber(int bitlen){
		BigInteger num = createBigNumber(bitlen);
				
		num = num.setBit(0); // ensure num is odd number ;)
		
		/* 
		 * A sieve here ;) 
		 * This solution boosts two or three times faster but It's still slower that JAVA lib implement
		 * 
		 * */
		int prime[] = {3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97};
		boolean[] sieve = new boolean[10009];
		int i;
		for (i = 0; i < prime.length; i++) {
			int m = num.mod(BigInteger.valueOf(prime[i])).intValue();
			int off = (prime[i] - m) % prime[i];
			for (int j=0; j < (10000 - off)/prime[i]; j++)
				sieve[off +j*prime[i]] = true;
		}
		
		int c = 0;
		BigInteger snum = num;
		while (!isPrime(num, 10)) {
			while (sieve[c] != false && c < 10000)  c +=2;
			
			//System.out.println("c  " + c);
			// increase c units
			num = snum.add(BigInteger.valueOf(c));
			c += 2;
			
			// check if now num > n^bitlen - 1, this is what we don't want!
			if (num.bitLength() > bitlen) 
				return createBigPrimeNumber(bitlen);
		}
		
		return num;
	}
	
	
	void showHelp() {
		System.err.println("Usage: java RSA BITSIZE FILENAME\nEncrypt FILENAME file with primes p,d size BITSIZE bits");
		System.exit(0);
	}
	
	int bitSize;
	String fileName;
	
	void run(String[] args) {

		/* 
		 * This below code checks randomness of our createBigNumber method
		 */
		if (DEBUG) {

			int[] count = new int[100];
			int i;
			for (i = 1; i <= 100000; i++) 
				count[createBigNumber(6).intValue()]++;
			
			for (i = 31; i<= 64; i++) System.out.print(count[i] + " ");
			
			System.out.println("\n");

			// check create prime number method
			// result: It works correctly but slow (FIX!)
			System.out.println(createBigPrimeNumber(512).toString());
			
			SecureRandom rnd = new SecureRandom();
			System.out.println(BigInteger.probablePrime(1024, rnd).toString());
		}

		if (args.length != 2) showHelp();

		try {
			/// TODO: bitSize = Integer.parser(args[0]);  DONE
			bitSize = Integer.parseInt(args[0]);
			fileName = args[1];
			
			BigInteger[] rl = createpq(bitSize);
			BigInteger p = rl[0];
			BigInteger q = rl[1];
			BigInteger e = finde(p, q);
			BigInteger d = findd(e, p, q);
			BigInteger n = p.multiply(q);
			
			
		} catch (Exception ex) {
			showHelp();
		}
			
	}

    public static void main(String[] args) {
        System.out.println("Welcome to Crypto Assignment\nAuthor: Thong Nguyen & Khoi Nguyen\n");
        
        new RSA().run(args);
    }

}
