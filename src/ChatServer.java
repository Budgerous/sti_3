import org.apache.log4j.Logger;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import java.util.StringTokenizer;


public class ChatServer implements Runnable {
    private ChatServerThread clients[] = new ChatServerThread[20];
    private BlockerThread blockerThread = null;
    private ServerSocket server_socket = null;
    private Thread thread = null;
    private int clientCount = 0;
    private static final String keyFile = Paths.get(".keys", "serverKeys").toString();
    PrivateKey privateKey = null;
    PublicKey publicKey = null;
    ArrayList<byte[]> blacklist = null;
    private byte[] password;
    private final static Logger LOGGER = Logger.getLogger("Server");

    public ChatServer(int port) {
        if (!setKeys()) {
            return;
        }
        try {
            // Binds to port and starts server
            LOGGER.info("Binding to port " + port);
            server_socket = new ServerSocket(port);
            LOGGER.info("Server started: " + server_socket);
            start();
        } catch (IOException ioexception) {
            // Error binding to port
            LOGGER.error("Binding error (port=" + port + "): " + ioexception.getMessage());
        }
    }

    public void run() {
        while (thread != null) {
            try {
                // Adds new thread for new client
                LOGGER.info("Waiting for a client ...");
                addThread(server_socket.accept());
            } catch (IOException ioexception) {
                LOGGER.error("Accept error: " + ioexception);
                stop();
            }
        }
    }

    private void start() {
        if (thread == null) {
            // Starts new thread for client
            thread = new Thread(this, "Running");
            thread.start();
        }
        if (blockerThread == null) {
            blockerThread = new BlockerThread(this);
            blockerThread.start();
        }
    }

    private void stop() {
        if (blockerThread != null) {
            blockerThread.close();
            blockerThread.stop();
            blockerThread = null;
        }
        if (thread != null) {
            // Stops running thread for client
            thread.stop();
            thread = null;
        }
    }

    private int findClient(int ID) {
        // Returns client from id
        for (int i = 0; i < clientCount; i++) {
            if (clients[i].getID() == ID) {
                return i;
            }
        }
        return -1;
    }

    synchronized void handle(int ID, String input) {
        if (input.equals(".quit")) {
            int leaving_id = findClient(ID);
            // Client exits
            clients[leaving_id].send(".quit");
            // Notify remaing users
            for (int i = 0; i < clientCount; i++) {
                if (i != leaving_id) {
                    clients[i].send("Client " + ID + " exits..");
                }
            }
            remove(ID);
        } else {
            System.out.println(ID + ": " + input);
            // Brodcast message for every other client online
            for (int i = 0; i < clientCount; i++) {
                clients[i].send(ID + ": " + input);
            }
        }
        clients[findClient(ID)].setCount(clients[findClient(ID)].getCount() + 1);
        if (clients[findClient(ID)].getCount() % 10 == 0) {
            clients[findClient(ID)].send(".renew");
            if (!clients[findClient(ID)].negotiateSymmetricKey()) {
                clients[findClient(ID)].send(".quit");
                remove(ID);
            }
        }
    }

    synchronized void remove(int ID) {
        int pos = findClient(ID);

        if (pos >= 0) {
            // Removes thread for exiting client
            ChatServerThread toTerminate = clients[pos];
            LOGGER.info("Removing client thread " + ID + " at " + pos);
            if (pos < clientCount - 1) {
                System.arraycopy(clients, pos + 1, clients, pos, clientCount - 1 - pos);
            }
            clientCount--;

            try {
                toTerminate.close();
            } catch (IOException ioe) {
                LOGGER.warn("Error closing thread: " + ioe);
            }

            toTerminate.stop();
        }
    }

    private void addThread(Socket socket) {
        if (clientCount < clients.length) {
            // Adds thread for new accepted client
            LOGGER.info("Client accepted: " + socket);
            clients[clientCount] = new ChatServerThread(this, socket);

            try {
                clients[clientCount].open();
                if (clients[clientCount].handShake()) {
                    clients[clientCount].start();
                    clientCount++;
                } else {
                    // clients[clientCount].send(".quit");
                    clients[clientCount].streamOut.writeInt(0);
                    clients[clientCount].streamOut.flush();
                    remove(clients[clientCount].getID());
                }
            } catch (IOException ioe) {
                LOGGER.warn("Error opening thread: " + ioe);
            }
        } else {
            LOGGER.warn("Client refused: maximum " + clients.length + " reached.");
        }
    }

    @SuppressWarnings("unchecked")
    private boolean setKeys() {
        System.out.println("Insert password: ");
        DataInputStream dis = new DataInputStream(System.in);
        password = new byte[32];
        FileInputStream fis = null;
        ObjectInputStream ois;

        // Read password and check if key file exists
        try {
            int ignored = dis.read(password, 0, 32);
            fis = new FileInputStream(keyFile);
        } catch (IOException e) {
            LOGGER.info("Generating new key file.");
        }

        // Key file doesn't exist
        if (fis == null) {
            FileOutputStream fos;
            ObjectOutputStream oos;
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
                blacklist = new ArrayList<>();

                SecretKeySpec spec = new SecretKeySpec(password, "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, spec);

                // First two entries are server keys
                blacklist.add(privateKey.getEncoded());
                blacklist.add(publicKey.getEncoded());
                // So that no user can login with the server keys
                blacklist.add(publicKey.getEncoded());

                for (int i = 0; i < blacklist.size(); i++) {
                    blacklist.set(i, cipher.doFinal(blacklist.get(i)));
                }

                oos.writeObject(blacklist);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
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
            blacklist = (ArrayList<byte[]>) ois.readObject();
            KeyFactory kf = KeyFactory.getInstance("RSA");

            SecretKeySpec spec = new SecretKeySpec(password, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, spec);

            for (int i = 0; i < blacklist.size(); i++) {
                blacklist.set(i, cipher.doFinal(blacklist.get(i)));
            }

            privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(blacklist.get(0)));
            publicKey = kf.generatePublic(new X509EncodedKeySpec(blacklist.get(1)));
            blacklist.remove(0);
            blacklist.remove(0);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException e) {
            LOGGER.error("Couldn't decrypt stored keys. Terminating.");
            return false;
        } catch (IOException | ClassNotFoundException e) {
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

    @SuppressWarnings("unchecked")
    void block(int ID) {
        if (findClient(ID) == -1) {
            return;
        }
        blacklist.add(clients[findClient(ID)].clientPublicKey.getEncoded());
        clients[findClient(ID)].send("Your account has been blocked.");
        clients[findClient(ID)].send(".quit");
        remove(ID);

        FileOutputStream fos = null;
        ObjectOutputStream oos = null;
        FileInputStream fis = null;
        ObjectInputStream ois = null;
        // Generate new key file
        try {
            fos = new FileOutputStream(keyFile);
            oos = new ObjectOutputStream(fos);
        } catch (IOException e) {
            LOGGER.error("Couldn't create key file. Terminating.");
            return;
        }

        // Create new array list for keys, where each entry is encrypted with AES and the given password
        try {
            SecretKeySpec spec = new SecretKeySpec(password, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, spec);

            blacklist.add(0, publicKey.getEncoded());
            blacklist.add(0, privateKey.getEncoded());
            for (int i = 0; i < blacklist.size(); i++) {
                blacklist.set(i, cipher.doFinal(blacklist.get(i)));
            }
            oos.writeObject(blacklist);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            LOGGER.error("Error encrypting keys to save. Terminating.");
            return;
        } catch (IOException e) {
            LOGGER.error("Couldn't store newly generated keys in file. Terminating.");
            return;
        }

        // Try and open the file again
        try {
            fis = new FileInputStream(keyFile);
            ois = new ObjectInputStream(fis);
        } catch (IOException e) {
            LOGGER.error("Couldn't read key file. Terminating.");
            return;
        }

        try {
            blacklist = (ArrayList<byte[]>) ois.readObject();
            KeyFactory kf = KeyFactory.getInstance("RSA");

            SecretKeySpec spec = new SecretKeySpec(password, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, spec);

            for (int i = 0; i < blacklist.size(); i++) {
                blacklist.set(i, cipher.doFinal(blacklist.get(i)));
            }

            privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(blacklist.get(0)));
            publicKey = kf.generatePublic(new X509EncodedKeySpec(blacklist.get(1)));
            blacklist.remove(0);
            blacklist.remove(0);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException e) {
            LOGGER.error("Couldn't decrypt stored keys. Terminating.");
        } catch (IOException | ClassNotFoundException e) {
            LOGGER.error("Couldn't read key file. Terminating.");
        }
    }

    void exit() {
        for (int i = clientCount - 1; i >= 0; i--) {
            clients[i].send(".quit");
            remove(clients[i].getID());
        }

        System.out.println("Exiting...Please press RETURN to exit ...");

        Scanner scanner = new Scanner(System.in);
        scanner.nextLine();
        System.exit(0);
    }

    public static void main(String args[]) {
        ChatServer server = null;

        if (args.length != 1) {
            // Displays correct usage for server
            System.out.println("Usage: java ChatServer port");
        } else {
            // Calls new server
            server = new ChatServer(Integer.parseInt(args[0]));
        }
    }

}

class BlockerThread extends Thread {
    private ChatServer server = null;
    private DataInputStream console = null;
    private final static Logger LOGGER = Logger.getLogger("Server");

    BlockerThread(ChatServer _server) {
        super("Blocker");
        server = _server;
    }

    public void run() {
        console = new DataInputStream(System.in);
        while (true) {
            try {
                String command = console.readLine();
                if (command.startsWith(".block")) {
                    StringTokenizer st = new StringTokenizer(command);
                    st.nextToken();
                    server.block(Integer.parseInt(st.nextToken()));
                } else if (command.compareTo(".quit") == 0) {
                    server.exit();
                }
            } catch (IOException e) {
                LOGGER.error("Error reading user command.");
                return;
            }
        }
    }

    void close() {
        if (console != null) {
            try {
                console.close();
            } catch (IOException e) {
                LOGGER.error("Error closing console.");
            }
        }
    }
}

class ChatServerThread extends Thread {
    private ChatServer server = null;
    private Socket socket = null;
    private int ID = -1;
    private int count = 0;
    private DataInputStream streamIn = null;
    DataOutputStream streamOut = null;
    PublicKey clientPublicKey = null;
    private SecretKey symmetricKey = null;
    private final static Logger LOGGER = Logger.getLogger("Server");

    int getCount() {
        return count;
    }

    void setCount(int count) {
        this.count = count;
    }

    ChatServerThread(ChatServer _server, Socket _socket) {
        super();
        server = _server;
        socket = _socket;
        ID = socket.getPort();
    }

    // Sends message to client
    void send(String msg) {
        byte[] toSend = null;
        byte[] signatureBytes = null;

        // Encrypt message
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            toSend = cipher.doFinal(msg.getBytes());
            LOGGER.info("Successfully encrypted message with symmetric key.");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Can't encrypt message with AES.");
            return;
        } catch (NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            LOGGER.error("Error encrypting message with AES.");
            return;
        } catch (InvalidKeyException e) {
            LOGGER.error("Can't encrypt message with your key.");
            return;
        }

        // Sign message
        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initSign(server.privateKey);
            signature.update(msg.getBytes());
            signatureBytes = signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            LOGGER.error("Can't sign message with your key.");
            return;
        }

        try {
            streamOut.writeInt(toSend.length);
            streamOut.flush();
            streamOut.write(toSend, 0, toSend.length);
            streamOut.flush();
            streamOut.write(signatureBytes, 0, 256);
            streamOut.flush();
        } catch (IOException ioexception) {
            LOGGER.error(ID + " ERROR sending message: " + ioexception.getMessage());
            server.remove(ID);
            stop();
        }
    }

    // Gets id for client
    int getID() {
        return ID;
    }

    // Runs thread
    public void run() {
        LOGGER.info("Server Thread " + ID + " running.");

        while (true) {
            try {
                int size = streamIn.readInt();
                byte[] input = new byte[size];
                int ignored = streamIn.read(input, 0, size);
                byte[] message = null;
                byte[] signatureBytes = new byte[256];
                ignored = streamIn.read(signatureBytes, 0, 256);
                boolean signed = false;

                // Decrypt message
                try {
                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
                    message = cipher.doFinal(input);
                    LOGGER.info("Decrypted received message.");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
                    LOGGER.error("Can't decrypt AES digests.");
                    return;
                }

                // Check signature
                try {
                    Signature signature = Signature.getInstance("SHA256WithRSA");
                    signature.initVerify(clientPublicKey);
                    signature.update(message);
                    signed = signature.verify(signatureBytes);
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                    LOGGER.error("Error checking signature.");
                }

                if (!signed) {
                    LOGGER.error("SECURITY BREACH! THIS MESSAGE WAS NOT SENT BY THIS USER!");
                    server.remove(ID);
                    stop();
                }

                server.handle(ID, new String(message));
            } catch (IOException ioe) {
                LOGGER.error(ID + " ERROR reading: " + ioe.getMessage());
                server.remove(ID);
                stop();
            }
        }
    }

    // Opens thread
    void open() throws IOException {
        streamIn = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        streamOut = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
    }

    // Closes thread
    void close() throws IOException {
        if (socket != null) {
            socket.close();
        }
        if (streamIn != null) {
            streamIn.close();
        }
        if (streamOut != null) {
            streamOut.close();
        }
    }

    boolean handShake() {
        // Get client public key
        try {
            int keyLength = streamIn.readInt();
            byte[] keyBytes = new byte[keyLength];
            int ignored = streamIn.read(keyBytes, 0, keyLength);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = null;
            keyFactory = KeyFactory.getInstance("RSA");
            clientPublicKey = keyFactory.generatePublic(pubKeySpec);
            LOGGER.info("Received public key from client.");
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

        // Check if client is blocked
        for (int i = 0; i < server.blacklist.size(); i++) {
            if (Arrays.equals(server.blacklist.get(i), clientPublicKey.getEncoded())) {
                LOGGER.error("User blocked. Terminating connection.");
                return false;
            }
        }

        // Send public key to client
        try {
            streamOut.writeInt(server.publicKey.getEncoded().length);
            streamOut.flush();
            streamOut.write(server.publicKey.getEncoded());
            streamOut.flush();
        } catch (IOException e) {
            LOGGER.error("Error sending public key to client.");
            return false;
        }

        if (!negotiateSymmetricKey()) {
            LOGGER.error("Error negotiating symmetric key.");
            return false;
        }

        LOGGER.info("Handshake completed.");
        return true;
    }

    boolean negotiateSymmetricKey() {
        byte[] encryptedSymmetricKey = null;
        byte[] decryptedSymmetricKey = null;
        byte[] encryptedSignature = null;
        byte[] signatureBytes = null;
        boolean result = false;

        // Get encrypted key
        try {
            int keyLength = streamIn.readInt();
            encryptedSymmetricKey = new byte[keyLength];
            int ignored = streamIn.read(encryptedSymmetricKey, 0, keyLength);
            LOGGER.info("Received encrypted symmetric key from client.");
        } catch (IOException e) {
            LOGGER.error("Error receiving encrypted symmetric key from socket.");
            return false;
        }

        // Decrypt symmetric key
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, server.privateKey);
            cipher.update(encryptedSymmetricKey);
            decryptedSymmetricKey = cipher.doFinal();
            symmetricKey = new SecretKeySpec(decryptedSymmetricKey, 0, decryptedSymmetricKey.length, "AES");
            LOGGER.info("Decrypted received symmetric key.");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Can't decrypt RSA digests.");
            return false;
        } catch (NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            LOGGER.error("Error decrypting symmetric key.");
            return false;
        } catch (InvalidKeyException e) {
            LOGGER.error("Invalid key. Can't decrypt symmetric key.");
            return false;
        }

        // Get encrypted signature
        try {
            int signLength = streamIn.readInt();
            encryptedSignature = new byte[signLength];
            int ignored = streamIn.read(encryptedSignature, 0, signLength);
            LOGGER.info("Received encrypted symmetric key signature from client.");
        } catch (IOException e) {
            LOGGER.error("Error receiving encrypted symmetric key signature from socket.");
            return false;
        }

        // Decrypt symmetric key signature
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            signatureBytes = cipher.doFinal(encryptedSignature);
            LOGGER.info("Decrypted received symmetric key signature.");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Can't decrypt AES digests.");
            return false;
        } catch (NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            LOGGER.error("Error decrypting symmetric key signature.");
            return false;
        } catch (InvalidKeyException e) {
            LOGGER.error("Invalid key. Can't decrypt symmetric key signature.");
            return false;
        }

        // Verify signature
        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initVerify(clientPublicKey);
            signature.update(decryptedSymmetricKey);
            result = signature.verify(signatureBytes);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Can't verify RSA signatures.");
            return false;
        } catch (SignatureException e) {
            LOGGER.error("Can't verify signature.");
            return false;
        } catch (InvalidKeyException e) {
            LOGGER.error("Can't verify signature with this key.");
            return false;
        }

        if (result) {
            LOGGER.info("Signature correctly verified. Saving symmetric key.");
        } else {
            LOGGER.error("Couldn't verify symmetric key signature.");
        }

        // Send ack to client
        try {
            streamOut.writeByte(6);
            streamOut.flush();
            LOGGER.info("Sending acknowledge message to client.");
        } catch (IOException e) {
            LOGGER.error("Error sending acknowledge message to client.");
            return false;
        }

        return result;
    }
}

