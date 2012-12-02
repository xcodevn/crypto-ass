import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

public class SSHFormat {

	private static final boolean DEBUG = false;

	private BigInteger readInputFile(String fileName) throws IOException {
		FileInputStream in = null;
		StringBuffer strContent = new StringBuffer("");

		try {
			in = new FileInputStream(fileName);
			int len;
			while ((len = in.read()) != -1) {
				strContent.append(len);
			}

			String string = new String(strContent);

			BigInteger bigInteger = new BigInteger(string);
			return bigInteger;

		} finally {
			if (in != null) {
				in.close();
			}
		}
	}

	private void writeOutputFile() {
		PrintStream out = null;
		try {
			out = new PrintStream(new FileOutputStream("key.pem"));
			out.print(keyPem);
			out.close();

			out = new PrintStream(new FileOutputStream("key.pub"));
			out.print(keyPub);
			out.close();

		} catch (FileNotFoundException ex) {
			ex.printStackTrace();
		}
	}

	BigInteger e;
	BigInteger d;
	BigInteger p;
	BigInteger q;
	String keyPub;
	String keyPem;

	public SSHFormat() throws IOException {
		// TODO Auto-generated constructor stub
		e = readInputFile("e.numb");
		d = readInputFile("d.numb");
		p = readInputFile("p.numb");
		q = readInputFile("q.numb");

	}

	public void run() throws IOException {
		PerformGenerateKeyPublic();
		PerformGenerateKeyPem();

		writeOutputFile();
	}

	public void test() {
		System.out.println(keyPub.toString());
		System.out.println("\n\n");
		System.out.println(keyPem.toString());
		
	}

	private void PerformGenerateKeyPem() throws IOException {
		// TODO Auto-generated method stub
		StringBuilder content = new StringBuilder();
		content.append("-----BEGIN PRIVACY-ENHANCED MESSAGE-----\n\n");

		/**
		 * Perform format here
		 */

		ByteArrayOutputStream out = new ByteArrayOutputStream();

		/* Write format identifier */
		byte[] sshrsa = new byte[] { 0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's',
				'a' };
		out.write(sshrsa);

		/* Encode the e */
		byte[] data = d.toByteArray();
		encodeUInt32(data.length, out);
		out.write(data);

		/* Encode the n */
		data = (p.multiply(q)).toByteArray();
		encodeUInt32(data.length, out);
		out.write(data);

		/* -------------------------------------------------- */
		String body = new String(DatatypeConverter.printBase64Binary(out
				.toByteArray()));

		if (DEBUG) {
			System.out.println("DEBUG");
			System.out.println(out);
			System.out.println(body);
		}

		content.append(splitStringFixedSize(body, 68));

		content.append("\n-----END PRIVACY-ENHANCED MESSAGE-----");

		keyPem = new String(content);
	}

	private void PerformGenerateKeyPublic() throws IOException {
		// TODO Auto-generated method stub
		StringBuilder content = new StringBuilder();
		content.append("---- BEGIN SSH2 PUBLIC KEY ----\n");

		/**
		 * Perform format here
		 */

		ByteArrayOutputStream out = new ByteArrayOutputStream();

		/* Write format identifier */
		byte[] sshrsa = new byte[] { 0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's',
				'a' };
		out.write(sshrsa);

		/* Encode the e */
		byte[] data = e.toByteArray();
		encodeUInt32(data.length, out);
		out.write(data);

		/* Encode the n */
		data = (p.multiply(q)).toByteArray();
		encodeUInt32(data.length, out);
		out.write(data);

		/* -------------------------------------------------- */
		String body = new String(DatatypeConverter.printBase64Binary(out
				.toByteArray()));

		if (DEBUG) {
			System.out.println("DEBUG");
			System.out.println(out);
			System.out.println(body);
			System.out.println(splitStringFixedSize(body, 68));
		}

		content.append(splitStringFixedSize(body, 68));

		content.append("\n---- END SSH2 PUBLIC KEY ----");

		keyPub = new String(content);
	}

	public static StringBuilder splitStringFixedSize(String str, int fixed_size)
	{
		int pos = 0;
		String tmp = "";
		StringBuilder result = new StringBuilder();
		List<String> returnValue = new ArrayList<String>((str.length()
				+ fixed_size - 1)/ fixed_size);

		for (pos = 0; pos < str.length(); pos += fixed_size)
		{
			tmp = str.substring(pos, Math.min(str.length(), pos + fixed_size));
			returnValue.add(tmp);
		}
		
		for (String string : returnValue) {
			result.append(string+ '\n');
		}

		return result;
	}

	public void encodeUInt32(int value, OutputStream out) throws IOException {
		byte[] tmp = new byte[4];
		tmp[0] = (byte) ((value >>> 24) & 0xff);
		tmp[1] = (byte) ((value >>> 16) & 0xff);
		tmp[2] = (byte) ((value >>> 8) & 0xff);
		tmp[3] = (byte) (value & 0xff);
		out.write(tmp);
	}

	public static void main(String[] args) throws IOException {
		SSHFormat sshFormat = new SSHFormat();
		sshFormat.run();
		sshFormat.test();
	}
}
