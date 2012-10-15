import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.BitSet;

import org.apache.commons.io.FileUtils;

public class lab3 {

	/**
	 * Exercise 1
	 * 
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		long p = Long.parseLong(args[0]);
		long q = Long.parseLong(args[1]);

		if (prime(p) && prime(q)) {
			System.out.println("Right enter");
			long n = p * q;
			long f_n = (p - 1) * (q - 1);

			System.out.println("n = " + n);
			System.out.println("f_n = " + f_n);

			if (f_n == 1) {
				System.out.println("You enter f_n == 1.");
				System.exit(1);
			}

			long e = 1;
			for (long i = 2; i < n; i++) {
				if (gcd(i, f_n) == 1) {
					e = i;
					break;
				}
			}

			System.out.println("e = " + e);

			writeToFile("e", e);
			writeToFile("n", n);

			long[] d = extendedEuclid(e, f_n);
			System.out.println("d = " + d[1]);
			writeToFile("d", d[1]);

			long size = (long) ((Math.log(n)/ Math.log(2)) / 8) ;
			System.out.println("size = " + size);
			
			encryptFile(size, n, e);
			decryptFile(size + 1, n, d[1]);
		} else {
			System.out.println("You have entered wrong prime number.");
		}

	}

	public static String bytesToString(byte[] encrypted) {
		String test = "";
		for (byte b : encrypted) {
			test += (Byte.toString(b) + " ");
		}
		return test;
	}

	/**
	 * Exercise 2
	 * 
	 * @param p
	 * @return
	 */
	public static boolean prime(long p) {

		if (p == 2) {
			return true;
		}
		// check if n is a multiple of 2
		if (p % 2 == 0 || p == 1)
			return false;
		// if not, then just check the odds
		for (long i = 3; i * i <= p; i += 2) {
			if (p % i == 0)
				return false;
		}

		return true;
	}

	/**
	 * Exercise 3
	 * 
	 * @param a
	 * @param b
	 * @return
	 */
	public static long gcd(long K, long M) {
		long k = Math.max(K, M);
		long m = Math.min(K, M);

		while (m != 0) {
			long r = k % m;
			k = m;
			m = r;
		}
		return k;
	}

	public static void writeToFile(String fileName, long value) {
		try {
			// Create file
			FileWriter fstream = new FileWriter(fileName + ".value");
			BufferedWriter out = new BufferedWriter(fstream);
			out.write(String.valueOf(value));
			// Close the output stream
			out.close();
		} catch (Exception exp) {// Catch exception if any
			System.err.println("Error: " + exp.getMessage());
		}
	}

	/**
	 * Exercise 4
	 * 
	 * @param d
	 * @param n
	 * @return
	 */
	public static long[] extendedEuclid(long a, long b) {
		long[] ans = new long[3];
		long q;

		if (b == 0) { /* If b = 0, then we're done... */
			ans[0] = a;
			ans[1] = 1;
			ans[2] = 0;
		} else { /* Otherwise, make a recursive function call */
			q = a / b;
			ans = extendedEuclid(b, a % b);
			long temp = ans[1] - ans[2] * q;
			ans[1] = ans[2];
			ans[2] = temp;
		}

		return ans;
	}

	/**
	 * Exercise 5
	 * 
	 * @param d
	 * @param n
	 * @param e
	 * @param e2 
	 * @return
	 * @throws IOException 
	 */
	public static void encryptFile(long size, long n, long e) throws IOException {
		cleanFile("cipher.txt");
		File desFile = new File("cipher.txt");
		File sourceFile = new File("input.txt");

		// Open the Plaintext file
		try {
			String str = FileUtils.readFileToString(sourceFile, "UTF8");

			// byte[] b1 = FileUtils.readFileToByteArray(sourceFile);
			byte[] b1 = str.getBytes();

			System.out.println("String from input.txt in byte = "
					+ bytesToString(b1));

			System.out.print("cipherText = ");
			for (int i = 0; i < b1.length; i += size) {
				byte[] tempByte = Arrays.copyOfRange(b1, i, (int) (i+size));
				

				BigInteger plainText = new BigInteger(tempByte);
				BigInteger cipherText = plainText.modPow(BigInteger.valueOf(e),
						BigInteger.valueOf(n));

				System.out.print(" " + cipherText);
			
				FileUtils.writeByteArrayToFile(desFile,
						padding((int) size + 1, cipherText.toByteArray()), true);
			}

			System.out.println();

		} catch (IOException err) {
			System.out.println("Cannot open file!");
			System.exit(-1);
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}
	
	public static byte[] padding(int numberOfByte, byte[] input){
		BitSet inputBit = BitSet.valueOf(input);
		BitSet formalBit = new BitSet(numberOfByte * 8);
		formalBit.or(inputBit);
		byte[] output = formalBit.toByteArray();
		return output;
		
	}

	public static void decryptFile(long size, long n, long d) throws IOException {
		cleanFile("decrypt.txt");
		File desFile = new File("decrypt.txt");
		File sourceFile = new File("cipher.txt");

		// Open the Plaintext file
		try {
			// String str = FileUtils.readFileToString(sourceFile);

			byte[] b1 = FileUtils.readFileToByteArray(sourceFile);

			System.out.println("String from cipher.txt in byte = "
					+ bytesToString(b1));

			System.out.print("plainText = ");
			
			for (int i = 0; i < b1.length; i += size) {
				byte[] tempByte = Arrays.copyOfRange(b1, i,
						(int) (i +size));

				BigInteger cipherText = new BigInteger(tempByte);
				
				BigInteger plainText = cipherText.modPow(BigInteger.valueOf(d),
						BigInteger.valueOf(n));
				System.out.print(" " + plainText);

				FileUtils.writeStringToFile(desFile,
						new String(plainText.toByteArray()), "UTF8", true);

			}
			
			System.out.println();

		} catch (IOException err) {
			System.out.println("Cannot open file!");
			System.exit(-1);
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}
	
	public static void cleanFile(String fileName) throws IOException{
		FileOutputStream erasor = new FileOutputStream(fileName);
		erasor.write((new String()).getBytes());
		erasor.close();
	}
}
