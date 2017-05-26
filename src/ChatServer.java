import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


public class ChatServer implements Runnable {
    private ChatServerThread clients[] = new ChatServerThread[20];
    private ServerSocket server_socket = null;
    private Thread thread = null;
    private int clientCount = 0;
    protected PrivateKey privateKey = null;
    protected PublicKey publicKey = null;

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

    private int findClient(int ID) {
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
        } else
            // Brodcast message for every other client online
            for (int i = 0; i < clientCount; i++)
                clients[i].send(ID + ": " + input);
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

    private boolean setKeys() {
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


    public static void main(String args[]) {
        ChatServer server = null;

        if (args.length != 1)
            // Displays correct usage for server
            System.out.println("Usage: java ChatServer port");
        else
            // Calls new server
            server = new ChatServer(Integer.parseInt(args[0]));
    }

}

class ChatServerThread extends Thread {
    private ChatServer server = null;
    private Socket socket = null;
    private int ID = -1;
    private DataInputStream streamIn = null;
    private DataOutputStream streamOut = null;
    private PublicKey clientPublicKey = null;
    private SecretKey symmetricKey = null;


    public ChatServerThread(ChatServer _server, Socket _socket) {
        super();
        server = _server;
        socket = _socket;
        ID = socket.getPort();
    }

    // Sends message to client
    public void send(String msg) {
        try {
            streamOut.writeUTF(msg);
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
                server.handle(ID, streamIn.readUTF());
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

    public boolean handShake() {
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

    private boolean negotiateSymmetricKey(){
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

