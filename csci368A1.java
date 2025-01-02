import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.util.Scanner;
import java.util.Scanner;
import java.math.BigInteger;
import java.util.Arrays;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class CSCI368_A1 {
    private static final String SYMMETRIC_KEY_ALGORITHM = "AES";

    private BigInteger alicePrivateKey;
    private BigInteger bobPrivateKey;

    // Generating random nonce
    private BigInteger generateNonce() {
        SecureRandom random = new SecureRandom();
        return new BigInteger(130, random);
    }

    // Message encryption with key
    private byte[] encrypt(SecretKey key, byte[] message) throws Exception {
        Cipher cp = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cp.init(Cipher.ENCRYPT_MODE, key);
        return cp.doFinal(message);
    }

    // Message decryption with key
    private byte[] decrypt(SecretKey key, byte[] encryptedMessage) throws Exception {
        Cipher cp = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cp.init(Cipher.DECRYPT_MODE, key);
        return cp.doFinal(encryptedMessage);
    }

    // Calculate the power of num
    private BigInteger pow(BigInteger base, BigInteger exponent, BigInteger modulus) {
        return base.modPow(exponent, modulus);
    }

    private SecretKey generateSymmetricKey(BigInteger bigInteger) {
        byte[] bigIntegerBytes = bigInteger.toByteArray();
        byte[] keyBytes = new byte[16];
        for (int i = 0; i < 16; i++) {

            if (i < bigIntegerBytes.length) {
                keyBytes[15 - i] = bigIntegerBytes[bigIntegerBytes.length - 1 - i];
            } else {
                keyBytes[15 - i] = 0;
            }
        }
        return new SecretKeySpec(keyBytes, SYMMETRIC_KEY_ALGORITHM);
    }

    public void senderActions(BigInteger senderPrivateKey, BigInteger receiverPublicKey, byte[] message,
            BigInteger p, BigInteger g) throws Exception {

        // Generate a random nonce r
        BigInteger r = generateNonce();

        // Calculate gr = g^r mod p
        BigInteger gr = pow(g, r, p);

        // Print sender's gr
        System.out.println("Sender's gr: " + gr.toString());

        // Calculate TK = receiverPublicKey^senderPrivateKey mod p
        BigInteger tk = pow(receiverPublicKey, senderPrivateKey, p);

        // Generate symmetric key from TK
        SecretKey key = generateSymmetricKey(tk);

        // Print sender's TK
        System.out.println("Sender's TK: " + Base64.getEncoder().encodeToString(tk.toByteArray()));

        // Encrypt the message using the symmetric key
        byte[] encryptedMessage = encrypt(key, message);

        // Print sender's message and encrypted message
        System.out.println("Sender's Message: " + new String(message));
        System.out.println("Sender's Encrypted Message: " + Base64.getEncoder().encodeToString(encryptedMessage));

        // Calculate LK = receiverPublicKey^senderPrivateKey mod p (Note: This line was
        // identical to calculating TK)
        BigInteger lk = pow(receiverPublicKey, senderPrivateKey, p);

        // Calculate MAC using lk, gr, and encryptedMessage
        byte[] mac = computeMAC(lk, gr, encryptedMessage);

        // Sending (g^r, C, MAC) to receiver
        receiverActions(senderPrivateKey, receiverPublicKey, gr, encryptedMessage, mac, p, g);
    }

    // Receiver's action
    public void receiverActions(BigInteger senderPrivateKey, BigInteger receiverPublicKey, BigInteger gr, byte[] c,
            byte[] mac, BigInteger p, BigInteger g) throws Exception {
        System.out.println("Receiver's gr: " + gr.toString());

        // Calculate TK
        BigInteger tk = pow(receiverPublicKey, senderPrivateKey, p);
        SecretKey key = generateSymmetricKey(tk);

        System.out.println("Receiver's TK: " + Base64.getEncoder().encodeToString(tk.toByteArray()));
        System.out.println("Receiver's Encrypted Message: " + Base64.getEncoder().encodeToString(c));

        // Calculate LK
        BigInteger lk = pow(receiverPublicKey, senderPrivateKey, p);

        // Compute MAC' = H(LK || g^r || C || LK)
        byte[] macPrime = computeMAC(lk, gr, c);

        // If MAC = MAC', go to the next step. Otherwise, output "ERROR"
        if (Arrays.equals(mac, macPrime)) {
            // Compute M' = D(TK, C)
            byte[] mPrime = decrypt(key, c);

            // decrypted message display
            System.out.println("Decrypted message: " + new String(mPrime));
        } else {
            System.out.println("ERROR: MAC values do not match!");
        }
    }

    // computing MAC
    private byte[] computeMAC(BigInteger lk, BigInteger gr, byte[] c) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");

        md.update(lk.toByteArray());
        md.update(gr.toByteArray());
        md.update(c);
        md.update(lk.toByteArray());

        return md.digest();
    }

    public static void main(String[] args) throws Exception {
        CSCI368_A1 app = new CSCI368_A1();

        // Read IP and port from input
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter IP address: ");
        String ip = scanner.nextLine();
        System.out.print("Enter port: ");
        int port = Integer.parseInt(scanner.nextLine());

        // Read public keys private keys for Alice
        System.out.print("Enter Alice's public key: ");
        String alicePublicKeyInput = scanner.nextLine();
        System.out.print("Enter Alice's private key: ");
        String alicePrivateKeyInput = scanner.nextLine();

        // Prime number and primitive root modulo p
        BigInteger p = new BigInteger("23");
        BigInteger g = new BigInteger("5");

        try {
            app.alicePrivateKey = new BigInteger(alicePrivateKeyInput);

            // Read Bob's public and private keys from input
            System.out.print("Enter Bob's public key: ");
            String bobPublicKeyInput = scanner.nextLine();
            System.out.print("Enter Bob's private key: ");
            String bobPrivateKeyInput = scanner.nextLine();

            app.bobPrivateKey = new BigInteger(bobPrivateKeyInput);

            // Connecting to the server
            System.out.println("Connecting to the server...");
            System.out.println("Connected!");
            System.out.println("Successfully connected to the server!");

            // Read Alice's message from input
            System.out.print("Alice's message: ");
            String aliceMessage = scanner.nextLine();
            app.senderActions(app.alicePrivateKey, new BigInteger(bobPublicKeyInput), aliceMessage.getBytes(), p, g);

            // Read Bob's message from input
            System.out.print("Bob's message: ");
            String bobMessage = scanner.nextLine();

            // Connecting and sending Bob's message to Alice
            System.out.println("Connecting to the server...");
            app.senderActions(app.bobPrivateKey, new BigInteger(alicePublicKeyInput), bobMessage.getBytes(), p, g);
            System.out.println("Connected!");
        } catch (NumberFormatException e) {
            System.out.println("ERROR: Invalid input. Please enter valid integer values for keys.");
        }

    }

}
