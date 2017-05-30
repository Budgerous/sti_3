import javax.crypto.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


public class ChatClient implements Runnable {
    private Socket socket = null;
    private Thread thread = null;
    private DataInputStream console = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client = null;
    protected PrivateKey privateKey = null;
    protected PublicKey publicKey = null;
    protected PublicKey serverPublicKey = null;
    protected SecretKey secretKey = null;

    public ChatClient(String serverName, int serverPort) {
        System.out.println("Establishing connection to server...");

        try {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);
            setStreams();
            if (handShake()) {
                start();
            } else {
                System.out.println("Terminating.");
                socket.close();
            }
        } catch (UnknownHostException uhe) {
            // Host unkwnown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage());
        } catch (IOException ioexception) {
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage());
        }

    }

    public void run() {
        while (thread != null) {
            try {
                // Sends message from console to server
                String input = console.readLine();
                byte[] toSend = null;

                // Encrypt message
                try {
                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    toSend = cipher.doFinal(input.getBytes());
                    System.out.println("Successfully encrypted message with symmetric key.");
                } catch (NoSuchAlgorithmException e) {
                    System.out.println("Can't encrypt message with AES.");
                    return;
                } catch (NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
                    System.out.println("Error.");
                    return;
                } catch (InvalidKeyException e) {
                    System.out.println("Can't encrypt message with your key.");
                    return;
                }

                streamOut.writeInt(toSend.length);
                streamOut.flush();
                streamOut.write(toSend, 0, toSend.length);
                streamOut.flush();
            } catch (IOException ioexception) {
                System.out.println("Error sending string to server: " + ioexception.getMessage());
                stop();
            }
        }
    }


    public void handle(String msg) {
        // Receives message from server
        if (msg.equals(".quit")) {
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        } else if(msg.equals(".renew")) {
            negotiateSymmetricKey();
        } else {
            // else, writes message received from server to console
            System.out.println(msg);
        }
    }

    private void setStreams() throws IOException {
        // Set streams from console and to socket
        console = new DataInputStream(System.in);
        streamOut = new DataOutputStream(socket.getOutputStream());
    }

    private boolean handShake() {
        // Generate key pair
        try {
            System.out.println("Generating key pair.");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGen.initialize(2048, random);

            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
            System.out.println("Key pair generated.");
        } catch (Exception e) {
            System.out.println("Error generating key pair.");
            return false;
        }

        // Send public key to server
        try {
            streamOut.writeInt(publicKey.getEncoded().length);
            streamOut.flush();
            streamOut.write(publicKey.getEncoded());
            streamOut.flush();
            System.out.println("Public key sent to server.");
        } catch (IOException e) {
            System.out.println("Error sending public key to server.");
            return false;
        }

        // Get server public key
        try {
            DataInputStream streamIn = new DataInputStream(socket.getInputStream());
            int keyLength = streamIn.readInt();
            byte[] keyBytes = new byte[keyLength];
            streamIn.read(keyBytes, 0, keyLength);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = null;
            keyFactory = KeyFactory.getInstance("RSA");
            serverPublicKey = keyFactory.generatePublic(pubKeySpec);
            System.out.println("Received public key from server.");
        } catch (IOException e) {
            System.out.println("Error receiving public key from socket.");
            return false;
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error generating key factory.");
            return false;
        } catch (InvalidKeySpecException e) {
            System.out.println("Error converting key.");
            return false;
        }

        if(!negotiateSymmetricKey()) {
            System.out.println("Error negotiating symmetric key.");
            return false;
        }

        System.out.println("Handshake completed.");
        return true;
    }

    private boolean negotiateSymmetricKey() {
        byte[] encryptedSymmKey = null;
        byte[] signedKey = null;
        byte[] encryptedSignature = null;
        // Generate symmetric key
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256, random);
            secretKey = keyGenerator.generateKey();
            System.out.println("Symmetric key generated.");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error generating symmetric key.");
            return false;
        }

        // Encrypt message
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            cipher.update(secretKey.getEncoded());
            encryptedSymmKey = cipher.doFinal();
            System.out.println("Successfully encrypted symmetric key with server public key.");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Can't encrypt message with RSA.");
            return false;
        } catch (NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
            System.out.println("Error.");
            return false;
        } catch (InvalidKeyException e) {
            System.out.println("Can't encrypt message with your key.");
            return false;
        }

        // Send message to server
        try {
            streamOut.writeInt(encryptedSymmKey.length);
            streamOut.flush();
            streamOut.write(encryptedSymmKey);
            streamOut.flush();
            System.out.println("Symmetric key sent to server.");
        } catch (IOException e) {
            System.out.println("Error sending symmetric key to server.");
            return false;
        }

        // Sign symmetric key
        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initSign(privateKey);
            signature.update(secretKey.getEncoded());
            signedKey = signature.sign();
            System.out.println("Symmetric key signed with private key.");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error generating key signer.");
            return false;
        } catch (SignatureException e) {
            System.out.println("Error signing key.");
            return false;
        } catch (InvalidKeyException e) {
            System.out.println("Error seeding private key for signature.");
            return false;
        }

        // Encrypt message
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            encryptedSignature = cipher.doFinal(signedKey);
            System.out.println("Successfully encrypted symmetric key signature with symmetric key.");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Can't encrypt message with AES.");
            return false;
        } catch (NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
            System.out.println("Error.");
            return false;
        } catch (InvalidKeyException e) {
            System.out.println("Can't encrypt message with your key.");
            return false;
        }

        // Send message to server
        try {
            streamOut.writeInt(encryptedSignature.length);
            streamOut.flush();
            streamOut.write(encryptedSignature);
            streamOut.flush();
            System.out.println("Symmetric key signature sent to server.");
        } catch (IOException e) {
            System.out.println("Error sending symmetric key signature to server.");
            return false;
        }

        // Receive ack from server
        try {
            DataInputStream streamIn = new DataInputStream(socket.getInputStream());
            byte success = streamIn.readByte();
            if(success == 6) {
                System.out.println("Received acknowledge message from server.");
            } else {
                System.out.println("Error receiving acknowledge message from server.");
                return false;
            }
        } catch (IOException e) {
            System.out.println("Error receiving acknowledge message from server.");
            return false;
        }

        return true;
    }

    // Inits new client thread
    public void start() throws IOException {
        if (thread == null) {
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);
            thread.start();
        }
    }

    // Stops client thread
    public void stop() {
        if (thread != null) {
            thread.stop();
            thread = null;
        }
        try {
            if (console != null) console.close();
            if (streamOut != null) streamOut.close();
            if (socket != null) socket.close();
        } catch (IOException ioe) {
            System.out.println("Error closing thread...");
        }
        client.close();
        client.stop();
    }


    public static void main(String args[]) {
        ChatClient client = null;
        if (args.length != 2)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port");
        else
            // Calls new client
            client = new ChatClient(args[0], Integer.parseInt(args[1]));
    }

}

class ChatClientThread extends Thread {
    private Socket socket = null;
    private ChatClient client = null;
    private DataInputStream streamIn = null;

    public ChatClientThread(ChatClient _client, Socket _socket) {
        client = _client;
        socket = _socket;
        open();
        start();
    }

    public void open() {
        try {
            streamIn = new DataInputStream(socket.getInputStream());
        } catch (IOException ioe) {
            System.out.println("Error getting input stream: " + ioe);
            client.stop();
        }
    }

    public void close() {
        try {
            if (streamIn != null) streamIn.close();
        } catch (IOException ioe) {
            System.out.println("Error closing input stream: " + ioe);
        }
    }

    public void run() {
        while (true) {
            try {
                int size = streamIn.readInt();
                byte[] input = new byte[size];
                streamIn.read(input, 0, size);
                byte[] toSend = null;

                // Decrypt symmetric key signature
                try {
                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.DECRYPT_MODE, client.secretKey);
                    toSend = cipher.doFinal(input);
                    System.out.println("Decrypted received message.");
                } catch (NoSuchAlgorithmException e) {
                    System.out.println("Can't decrypt AES digests.");
                    continue;
                } catch (NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
                    System.out.println("Error.");
                    continue;
                } catch (InvalidKeyException e) {
                    System.out.println("Invalid key. Can't decrypt symmetric key signature.");
                    continue;
                }

                client.handle(new String(toSend));
            } catch (IOException ioe) {
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            }
        }
    }
}

