import org.apache.log4j.Logger;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;


public class ChatClient implements Runnable {
    private Socket socket = null;
    private Thread thread = null;
    private DataInputStream console = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client = null;
    private PrivateKey privateKey = null;
    private PublicKey publicKey = null;
    PublicKey serverPublicKey = null;
    SecretKey secretKey = null;
    private final static Logger LOGGER = Logger.getLogger("Client");

    public ChatClient(String serverName, int serverPort) {
        LOGGER.info("Establishing connection to server...");

        try {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
            LOGGER.info("Connected to server: " + socket);
            setStreams();
            if (handShake()) {
                start();
            } else {
                LOGGER.error("Terminating.");
                socket.close();
            }
        } catch (UnknownHostException uhe) {
            // Host unkwnown
            LOGGER.error("Error establishing connection - host unknown: " + uhe.getMessage());
        } catch (IOException ioexception) {
            // Other error establishing connection
            LOGGER.error("Error establishing connection - unexpected exception: " + ioexception.getMessage());
        }

    }

    public void run() {
        while (thread != null) {
            try {
                // Sends message from console to server
                String input = console.readLine();
                byte[] toSend = null;
                byte[] signatureBytes = null;

                // Encrypt message
                try {
                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    toSend = cipher.doFinal(input.getBytes());
                    LOGGER.info("Successfully encrypted message with symmetric key.");
                } catch (NoSuchAlgorithmException e) {
                    LOGGER.error("Can't encrypt message with AES.");
                    return;
                } catch (NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
                    LOGGER.error("Error encrypting message.");
                    return;
                } catch (InvalidKeyException e) {
                    LOGGER.error("Can't encrypt message with your key.");
                    stop();
                    return;
                }

                // Sign message
                try {
                    Signature signature = Signature.getInstance("SHA256WithRSA");
                    signature.initSign(privateKey);
                    signature.update(input.getBytes());
                    signatureBytes = signature.sign();
                } catch (NoSuchAlgorithmException|InvalidKeyException|SignatureException e) {
                    LOGGER.error("Error signing message.");
                    stop();
                    return;
                }

                streamOut.writeInt(toSend.length);
                streamOut.flush();
                streamOut.write(toSend, 0, toSend.length);
                streamOut.flush();
                streamOut.write(signatureBytes, 0, 256);
                streamOut.flush();
            } catch (IOException ioexception) {
                LOGGER.error("Error sending string to server: " + ioexception.getMessage());
                stop();
            }
        }
    }

    @SuppressWarnings("unchecked")
    private boolean setKeys() {
        DataInputStream dis = new DataInputStream(System.in);
        byte[] password = new byte[32];
        FileInputStream fis = null;
        ObjectInputStream ois = null;
        boolean fileExists = true;

        // Read username and password
        String keyFile;
        try {
            System.out.println("Insert username: ");
            String username = dis.readLine();
            System.out.println("Insert password: ");
            int ignored = dis.read(password, 0, 32);
            keyFile = Paths.get(".keys", username.concat(".keys")).toString();
        } catch (IOException e) {
            LOGGER.error("Something went horribly wrong. We're soory.");
            return false;
        }


        // Check if key file exists
        try {
            fis = new FileInputStream(keyFile);
        } catch (IOException e) {
            LOGGER.info("Generating new key file.");
        }

        // Key file doesn't exist
        if(fis == null) {
            fileExists = false;
            FileOutputStream fos = null;
            ObjectOutputStream oos = null;
            // Generate new key file
            try {
                fos = new FileOutputStream(keyFile);
                oos = new ObjectOutputStream(fos);
            } catch (IOException e) {
                LOGGER.error("Couldn't create key file. Terminating.");
                return false;
            }

            generateKeys();

            // Create new array list for keys, where each entry is encrypted with AES and the given password
            try {
                ArrayList<byte[]> keyList = new ArrayList<>();

                SecretKeySpec spec = new SecretKeySpec(password, "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, spec);

                // First two entries are server keys
                keyList.add(cipher.doFinal(privateKey.getEncoded()));
                keyList.add(cipher.doFinal(publicKey.getEncoded()));

                oos.writeObject(keyList);
            } catch (NoSuchAlgorithmException|NoSuchPaddingException|InvalidKeyException|IllegalBlockSizeException|BadPaddingException e) {
                LOGGER.error("Couldn't encrypt newly generated keys. Terminating");
                return false;
            } catch (IOException e) {
                LOGGER.error("Couldn't store newly generated keys in file. Terminating.");
                return false;
            }
        }

        // Try and open the file again
        try {
            fis = new FileInputStream(keyFile);
            ois = new ObjectInputStream(fis);
        } catch (IOException e) {
            LOGGER.error("Couldn't read key file. Terminating.");
            return false;
        }

        try {
            ArrayList<byte[]> keyList = (ArrayList<byte[]>)ois.readObject();
            KeyFactory kf = KeyFactory.getInstance("RSA");

            SecretKeySpec spec = new SecretKeySpec(password, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, spec);

            privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(cipher.doFinal(keyList.get(0))));
            publicKey = kf.generatePublic(new X509EncodedKeySpec(cipher.doFinal(keyList.get(1))));
        } catch (NoSuchAlgorithmException|NoSuchPaddingException|InvalidKeyException|IllegalBlockSizeException|BadPaddingException|InvalidKeySpecException e) {
            if(fileExists) {
                LOGGER.error("Wrong username or password. Try again.");
            } else {
                LOGGER.error("Couldn't decrypt stored keys. Terminating.");
            }
            return false;
        } catch (IOException|ClassNotFoundException e) {
            LOGGER.error("Couldn't read key file. Terminating.");
            return false;
        }

        return true;
    }

    private boolean generateKeys() {
        // Generate key pair
        try {
            LOGGER.info("Generating key pair.");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGen.initialize(2048, random);

            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
            LOGGER.info("Key pair generated.");
        } catch (Exception e) {
            LOGGER.error("Error generating key pair.");
            return false;
        }
        return true;
    }

    void handle(String msg) {
        // Receives message from server
        switch (msg) {
            case ".quit": {
                // Leaving, quit command
                System.out.println("Exiting...Please press RETURN to exit ...");
                stop();
                break;
            } case ".renew": {
                negotiateSymmetricKey();
                break;
            } default: {
                // else, writes message received from server to console
                System.out.println(msg);
                break;
            }
        }
    }

    private void setStreams() throws IOException {
        // Set streams from console and to socket
        console = new DataInputStream(System.in);
        streamOut = new DataOutputStream(socket.getOutputStream());
    }

    private boolean handShake() {
        if(!setKeys()) {
            LOGGER.error("Couldn't generate keys.");
            return false;
        }

        // Send public key to server
        try {
            streamOut.writeInt(publicKey.getEncoded().length);
            streamOut.flush();
            streamOut.write(publicKey.getEncoded());
            streamOut.flush();
            LOGGER.info("Public key sent to server.");
        } catch (IOException e) {
            LOGGER.error("Error sending public key to server.");
            return false;
        }

        // Get server public key
        try {
            DataInputStream streamIn = new DataInputStream(socket.getInputStream());
            int keyLength = streamIn.readInt();

            if(keyLength == 0) {
                LOGGER.error("You have been blocked. Terminating.");
                return false;
            }

            byte[] keyBytes = new byte[keyLength];
            streamIn.read(keyBytes, 0, keyLength);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = null;
            keyFactory = KeyFactory.getInstance("RSA");
            serverPublicKey = keyFactory.generatePublic(pubKeySpec);
            LOGGER.info("Received public key from server.");
        } catch (IOException e) {
            LOGGER.error("Error receiving public key from socket.");
            return false;
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Error generating key factory.");
            return false;
        } catch (InvalidKeySpecException e) {
            LOGGER.error("Error converting key.");
            return false;
        }

        if(!negotiateSymmetricKey()) {
            LOGGER.error("Error negotiating symmetric key.");
            return false;
        }

        LOGGER.info("Handshake completed.");
        return true;
    }

    private boolean negotiateSymmetricKey() {
        byte[] encryptedSymmKey;
        byte[] signedKey;
        byte[] encryptedSignature;

        // Generate symmetric key
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256, random);
            secretKey = keyGenerator.generateKey();
            LOGGER.info("Symmetric key generated.");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Error generating symmetric key.");
            return false;
        }

        // Encrypt message
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            cipher.update(secretKey.getEncoded());
            encryptedSymmKey = cipher.doFinal();
            LOGGER.info("Successfully encrypted symmetric key with server public key.");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Can't encrypt message with RSA.");
            return false;
        } catch (NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
            LOGGER.error("Error encrypting message.");
            return false;
        } catch (InvalidKeyException e) {
            LOGGER.error("Can't encrypt message with your key.");
            return false;
        }

        // Send message to server
        try {
            streamOut.writeInt(encryptedSymmKey.length);
            streamOut.flush();
            streamOut.write(encryptedSymmKey);
            streamOut.flush();
            LOGGER.info("Symmetric key sent to server.");
        } catch (IOException e) {
            LOGGER.error("Error sending symmetric key to server.");
            return false;
        }

        // Sign symmetric key
        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initSign(privateKey);
            signature.update(secretKey.getEncoded());
            signedKey = signature.sign();
            LOGGER.info("Symmetric key signed with private key.");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Error generating key signer.");
            return false;
        } catch (SignatureException e) {
            LOGGER.error("Error signing key.");
            return false;
        } catch (InvalidKeyException e) {
            LOGGER.error("Error seeding private key for signature.");
            return false;
        }

        // Encrypt message
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            encryptedSignature = cipher.doFinal(signedKey);
            LOGGER.info("Successfully encrypted symmetric key signature with symmetric key.");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Can't encrypt message with AES.");
            return false;
        } catch (NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
            LOGGER.error("Error encrypting message.");
            return false;
        } catch (InvalidKeyException e) {
            LOGGER.error("Can't encrypt message with your key.");
            return false;
        }

        // Send message to server
        try {
            streamOut.writeInt(encryptedSignature.length);
            streamOut.flush();
            streamOut.write(encryptedSignature);
            streamOut.flush();
            LOGGER.info("Symmetric key signature sent to server.");
        } catch (IOException e) {
            LOGGER.error("Error sending symmetric key signature to server.");
            return false;
        }

        // Receive ack from server
        try {
            DataInputStream streamIn = new DataInputStream(socket.getInputStream());
            byte success = streamIn.readByte();
            if(success == 6) {
                LOGGER.info("Received acknowledge message from server.");
            } else {
                LOGGER.error("Error receiving acknowledge message from server.");
                return false;
            }
        } catch (IOException e) {
            LOGGER.error("Error receiving acknowledge message from server.");
            return false;
        }

        return true;
    }

    // Inits new client thread
    private void start() throws IOException {
        if (thread == null) {
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);
            thread.start();
        }
    }

    // Stops client thread
    void stop() {
        if (thread != null) {
            thread.stop();
            thread = null;
        }
        try {
            if (console != null) {
                console.close();
            }
            if (streamOut != null) {
                streamOut.close();
            }
            if (socket != null) {
                socket.close();
            }
        } catch (IOException ioe) {
            LOGGER.error("Error closing thread...");
        }
        client.close();
        client.stop();
    }

    public static void main(String args[]) {
        if (args.length != 2) {
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port");
        } else {
            // Calls new client
            new ChatClient(args[0], Integer.parseInt(args[1]));
        }
    }
}

class ChatClientThread extends Thread {
    private Socket socket = null;
    private ChatClient client = null;
    private DataInputStream streamIn = null;
    private final static Logger LOGGER = Logger.getLogger("Client");

    ChatClientThread(ChatClient _client, Socket _socket) {
        client = _client;
        socket = _socket;
        open();
        start();
    }

    private void open() {
        try {
            streamIn = new DataInputStream(socket.getInputStream());
        } catch (IOException ioe) {
            LOGGER.error("Error getting input stream: " + ioe);
            client.stop();
        }
    }

    void close() {
        try {
            if (streamIn != null) {
                streamIn.close();
            }
        } catch (IOException ioe) {
            LOGGER.error("Error closing input stream: " + ioe);
        }
    }

    public void run() {
        while (true) {
            try {
                int size = streamIn.readInt();
                byte[] input = new byte[size];
                int ignored = streamIn.read(input, 0, size);
                byte[] message;
                byte[] signatureBytes = new byte[256];
                ignored = streamIn.read(signatureBytes, 0, 256);
                boolean signed = false;

                // Decrypt message
                try {
                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.DECRYPT_MODE, client.secretKey);
                    message = cipher.doFinal(input);
                    LOGGER.info("Decrypted received message.");
                } catch (NoSuchAlgorithmException|NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException|InvalidKeyException e) {
                    LOGGER.error("Can't decrypt AES digests.");
                    return;
                }

                // Check signature
                try {
                    Signature signature = Signature.getInstance("SHA256WithRSA");
                    signature.initVerify(client.serverPublicKey);
                    signature.update(message);
                    signed = signature.verify(signatureBytes);
                } catch (NoSuchAlgorithmException|InvalidKeyException|SignatureException e) {
                    LOGGER.error("Error checking signature.");
                    return;
                }

                if(!signed) {
                    LOGGER.error("SECURITY BREACH! THIS MESSAGE WAS NOT SENT BY THE SERVER!");
                    client.stop();
                    return;
                }

                client.handle(new String(message));
            } catch (IOException ioe) {
                LOGGER.error("Listening error: " + ioe.getMessage());
                client.stop();
                return;
            }
        }
    }
}

