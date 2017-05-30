import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.StringTokenizer;


public class ChatServer implements Runnable {
    private ChatServerThread clients[] = new ChatServerThread[20];
    private ServerSocket server_socket = null;
    private Thread thread = null;
    private int clientCount = 0;
    PrivateKey privateKey = null;
    PublicKey publicKey = null;
    ArrayList<byte[]> blacklist = null;
    byte[] password;

    public ChatServer(int port) {
        if(!setKeys()) {
            return;
        }
        try {
            // Binds to port and starts server
            System.out.println("Binding to port " + port);
            server_socket = new ServerSocket(port);
            System.out.println("Server started: " + server_socket);
            start();
        } catch (IOException ioexception) {
            // Error binding to port
            System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
        }
    }

    public void run() {
        while (thread != null) {
            try {
                // Adds new thread for new client
                System.out.println("Waiting for a client ...");
                addThread(server_socket.accept());
            } catch (IOException ioexception) {
                System.out.println("Accept error: " + ioexception);
                stop();
            }
        }
    }

    public void start() {
        if (thread == null) {
            // Starts new thread for client
            thread = new Thread(this);
            thread.start();
        }
    }

    public void stop() {
        if (thread != null) {
            // Stops running thread for client
            thread.stop();
            thread = null;
        }
    }

    int findClient(int ID) {
        // Returns client from id
        for (int i = 0; i < clientCount; i++)
            if (clients[i].getID() == ID)
                return i;
        return -1;
    }

    public synchronized void handle(int ID, String input) {
        if (input.equals(".quit")) {
            int leaving_id = findClient(ID);
            // Client exits
            clients[leaving_id].send(".quit");
            // Notify remaing users
            for (int i = 0; i < clientCount; i++)
                if (i != leaving_id)
                    clients[i].send("Client " + ID + " exits..");
            remove(ID);
        } else {
            System.out.println(ID + ": " + input);
            // Brodcast message for every other client online
            for (int i = 0; i < clientCount; i++)
                clients[i].send(ID + ": " + input);
        }
        clients[findClient(ID)].setCount(clients[findClient(ID)].getCount() + 1);
        if(clients[findClient(ID)].getCount()%10 == 0) {
            clients[findClient(ID)].send(".renew");
            if(!clients[findClient(ID)].negotiateSymmetricKey()) {
                clients[findClient(ID)].send(".quit");
                remove(ID);
            }
        }
    }

    public synchronized void remove(int ID) {
        int pos = findClient(ID);

        if (pos >= 0) {
            // Removes thread for exiting client
            ChatServerThread toTerminate = clients[pos];
            System.out.println("Removing client thread " + ID + " at " + pos);
            if (pos < clientCount - 1)
                for (int i = pos + 1; i < clientCount; i++)
                    clients[i - 1] = clients[i];
            clientCount--;

            try {
                toTerminate.close();
            } catch (IOException ioe) {
                System.out.println("Error closing thread: " + ioe);
            }

            toTerminate.stop();
        }

        FileOutputStream fos = null;
        ObjectOutputStream oos = null;
        try {
            fos = new FileOutputStream("serverKeys");
            oos = new ObjectOutputStream(fos);
        } catch (IOException ignored) {
        }

        if(fos != null) {
            try {
                ArrayList<byte[]> keys = new ArrayList<>();

                SecretKeySpec spec = new SecretKeySpec(password, "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, spec);

                keys.add(cipher.doFinal(privateKey.getEncoded()));
                keys.add(cipher.doFinal(publicKey.getEncoded()));

                for(byte[] each : blacklist) {
                    keys.add(each);
                }

                oos.writeObject(keys);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void addThread(Socket socket) {
        if (clientCount < clients.length) {
            // Adds thread for new accepted client
            System.out.println("Client accepted: " + socket);
            clients[clientCount] = new ChatServerThread(this, socket);

            try {
                clients[clientCount].open();
                if (clients[clientCount].handShake()) {
                    clients[clientCount].start();
                    clientCount++;
                } else {
                    clients[clientCount].send(".quit");
                    remove(clients[clientCount].getID());
                }
            } catch (IOException ioe) {
                System.out.println("Error opening thread: " + ioe);
            }
        } else
            System.out.println("Client refused: maximum " + clients.length + " reached.");
    }

    public boolean setKeys() {
        System.out.println("Insert password: ");
        DataInputStream dis = new DataInputStream(System.in);
        password = new byte[32];
        FileInputStream fis = null;
        ObjectInputStream ois = null;

        try {
            dis.read(password, 0, 32);
            fis = new FileInputStream("serverKeys");
        } catch (IOException ignored) {

        }

        if(fis == null) {
            FileOutputStream fos = null;
            ObjectOutputStream oos = null;
            try {
                fos = new FileOutputStream("serverKeys");
                oos = new ObjectOutputStream(fos);
            } catch (IOException e) {
                e.printStackTrace();
            }

            generateKeys();

            if(fos != null) {
                try {
                    ArrayList<byte[]> keys = new ArrayList<>();

                    SecretKeySpec spec = new SecretKeySpec(password, "AES");
                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.ENCRYPT_MODE, spec);

                    keys.add(cipher.doFinal(privateKey.getEncoded()));
                    keys.add(cipher.doFinal(publicKey.getEncoded()));

                    oos.writeObject(keys);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        fis = null;
        ois = null;

        try {
            fis = new FileInputStream("serverKeys");
            ois = new ObjectInputStream(fis);
        } catch (IOException ignored) {

        }

        if(ois != null) {
            try {
                blacklist = (ArrayList<byte[]>)ois.readObject();
                KeyFactory kf = KeyFactory.getInstance("RSA");

                SecretKeySpec spec = new SecretKeySpec(password, "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, spec);

                privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(cipher.doFinal(blacklist.get(0))));
                publicKey = kf.generatePublic(new X509EncodedKeySpec(cipher.doFinal(blacklist.get(1))));
                blacklist.remove(0);
                blacklist.remove(0);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return true;
    }

    private boolean generateKeys() {
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
        return true;
    }

    void block(int ID) {
        if(findClient(ID) == -1) {
            return;
        }
        blacklist.add(clients[findClient(ID)].clientPublicKey.getEncoded());
        clients[findClient(ID)].send("Your account has been blocked.");
        clients[findClient(ID)].send(".quit");
        remove(ID);
    }

    public static void main(String args[]) {
        ChatServer server = null;

        if (args.length != 1)
            // Displays correct usage for server
            System.out.println("Usage: java ChatServer port");
        else {
            // Calls new server
            server = new ChatServer(Integer.parseInt(args[0]));
            BlockerThread blockerThread = new BlockerThread(server);
            blockerThread.start();
        }
    }

}

class BlockerThread extends Thread {
    private ChatServer server = null;
    public BlockerThread(ChatServer _server) {
        super();
        server = _server;
    }

    public void run() {
        DataInputStream console = new DataInputStream(System.in);
        while(true) {
            try {
                String command = console.readLine();
                if(command.startsWith(".block")) {
                    StringTokenizer st = new StringTokenizer(command);
                    st.nextToken();
                    server.block(Integer.parseInt(st.nextToken()));
                }
            } catch (IOException e) {
                e.printStackTrace();
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
    private DataOutputStream streamOut = null;
    PublicKey clientPublicKey = null;
    private SecretKey symmetricKey = null;

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }

    public ChatServerThread(ChatServer _server, Socket _socket) {
        super();
        server = _server;
        socket = _socket;
        ID = socket.getPort();
    }

    // Sends message to client
    public void send(String msg) {
        byte[] toSend = null;

        // Encrypt message
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            toSend = cipher.doFinal(msg.getBytes());
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

        try {
            streamOut.writeInt(toSend.length);
            streamOut.flush();
            streamOut.write(toSend, 0, toSend.length);
            streamOut.flush();
        } catch (IOException ioexception) {
            System.out.println(ID + " ERROR sending message: " + ioexception.getMessage());
            server.remove(ID);
            stop();
        }
    }

    // Gets id for client
    public int getID() {
        return ID;
    }

    // Runs thread
    public void run() {
        System.out.println("Server Thread " + ID + " running.");

        while (true) {
            try {
                int size = streamIn.readInt();
                byte[] input = new byte[size];
                streamIn.read(input, 0, size);
                byte[] toSend = null;

                // Decrypt message
                try {
                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
                    toSend = cipher.doFinal(input);
                    System.out.println("Decrypted received message.");
                } catch (NoSuchAlgorithmException e) {
                    System.out.println("Can't decrypt AES digests.");
                    continue;
                } catch (NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
                    System.out.println("Error.");
                    e.printStackTrace();
                    continue;
                } catch (InvalidKeyException e) {
                    System.out.println("Invalid key. Can't decrypt symmetric key signature.");
                    continue;
                }

                server.handle(ID, new String(toSend));
            } catch (IOException ioe) {
                System.out.println(ID + " ERROR reading: " + ioe.getMessage());
                server.remove(ID);
                stop();
            }
        }
    }


    // Opens thread
    public void open() throws IOException {
        streamIn = new DataInputStream(new
                BufferedInputStream(socket.getInputStream()));
        streamOut = new DataOutputStream(new
                BufferedOutputStream(socket.getOutputStream()));
    }

    // Closes thread
    public void close() throws IOException {
        if (socket != null) socket.close();
        if (streamIn != null) streamIn.close();
        if (streamOut != null) streamOut.close();
    }

    boolean handShake() {
        // Get client public key
        try {
            int keyLength = streamIn.readInt();
            byte[] keyBytes = new byte[keyLength];
            streamIn.read(keyBytes, 0, keyLength);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = null;
            keyFactory = KeyFactory.getInstance("RSA");
            clientPublicKey = keyFactory.generatePublic(pubKeySpec);
            System.out.println("Received public key from client.");
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

        for(byte[] each : server.blacklist) {
            System.out.println(each);
        }

        if(server.blacklist.indexOf(clientPublicKey.getEncoded()) != -1 ) {
            System.out.println("User blocked. Terminating connection.");
            return false;
        }

        // Send public key to client
        try {
            streamOut.writeInt(server.publicKey.getEncoded().length);
            streamOut.flush();
            streamOut.write(server.publicKey.getEncoded());
            streamOut.flush();
        } catch (IOException e) {
            System.out.println("Error sending public key to client.");
            return false;
        }

        if(!negotiateSymmetricKey()) {
            System.out.println("Error negotiating symmetric key.");
            return false;
        }

        System.out.println("Handshake completed.");
        return true;
    }

    boolean negotiateSymmetricKey(){
        byte[] encryptedSymmetricKey = null;
        byte[] decryptedSymmetricKey = null;
        byte[] encryptedSignature = null;
        byte[] signatureBytes = null;
        boolean result = false;
        // Get encrypted key
        try {
            int keyLength = streamIn.readInt();
            encryptedSymmetricKey = new byte[keyLength];
            streamIn.read(encryptedSymmetricKey, 0, keyLength);
            System.out.println("Received encrypted symmetric key from client.");
        } catch (IOException e) {
            System.out.println("Error receiving encrypted symmetric key from socket.");
            return false;
        }

        // Decrypt symmetric key
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, server.privateKey);
            cipher.update(encryptedSymmetricKey);
            decryptedSymmetricKey = cipher.doFinal();
            symmetricKey = new SecretKeySpec(decryptedSymmetricKey, 0, decryptedSymmetricKey.length, "AES");
            System.out.println("Decrypted received symmetric key.");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Can't decrypt RSA digests.");
            return false;
        } catch (NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
            System.out.println("Error.");
            return false;
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key. Can't decrypt symmetric key.");
            return false;
        }

        // Get encrypted signature
        try {
            int signLength = streamIn.readInt();
            encryptedSignature = new byte[signLength];
            streamIn.read(encryptedSignature, 0, signLength);
            System.out.println("Received encrypted symmetric key signature from client.");
        } catch (IOException e) {
            System.out.println("Error receiving encrypted symmetric key signature from socket.");
            return false;
        }

        // Decrypt symmetric key signature
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            signatureBytes = cipher.doFinal(encryptedSignature);
            System.out.println("Decrypted received symmetric key signature.");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Can't decrypt AES digests.");
            return false;
        } catch (NoSuchPaddingException|BadPaddingException|IllegalBlockSizeException e) {
            System.out.println("Error.");
            return false;
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key. Can't decrypt symmetric key signature.");
            return false;
        }

        // Verify signature
        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initVerify(clientPublicKey);
            signature.update(decryptedSymmetricKey);
            result = signature.verify(signatureBytes);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Can't verify RSA signatures.");
            return false;
        } catch (SignatureException e) {
            e.printStackTrace();
            System.out.println("Can't verify signature.");
            return false;
        } catch (InvalidKeyException e) {
            System.out.println("Can't verify signature with this key.");
            return false;
        }

        if(result) {
            System.out.println("Signature correctly verified. Saving symmetric key.");
        } else {
            System.out.println("Couldn't verify symmetric key signature.");
        }

        // Send ack to client
        try {
            streamOut.writeByte(6);
            streamOut.flush();
            System.out.println("Sending acknowledge message to client.");
        } catch (IOException e) {
            System.out.println("Error sending acknowledge message to client.");
            return false;
        }

        return result;
    }
}

