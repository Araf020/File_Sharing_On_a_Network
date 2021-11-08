package com.arafat.server;

import com.arafat.message.Message;
import com.arafat.security.RSA;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Scanner;
import java.util.StringTokenizer;
import java.util.Vector;

public class Server {

    //to store active clients
    static Vector<ClientHandler> clientList = new Vector<>();
    static  int clientCounter = 0;

    private Cipher keydecipher;
    private Cipher serveDecrypt;
    private Cipher serverEncrypt;
    SecretKey AESKey;
    int flag;

    byte[] input;
    int port;
    private Message sendMsg;
    private Message rcvdmsg;
    static String IV = "AAAAAAAAAAAAAAAA";


//    public Server(int port){
//        this.port = port;
//    }

//    public void initializeServer() throws IOException {
//        ServerSocket serverSocket = new ServerSocket(9090);
//        System.out.println("Server started");
//        Socket socket = serverSocket.accept();
//
//        ClientHandler clientHandler = newClie
//    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        ServerSocket serverSocket = new ServerSocket(9090);
        System.out.println("Server Started");

        Socket socket;

        //creating public and private keys
        RSA rsa = new RSA();
        rsa.createRSA();
        System.out.println("rsa creation completed..");

        while(true){
            socket = serverSocket.accept();
            System.out.println("new Client Connected " + socket.getInetAddress());
            System.out.println("wth!!");

            //get input and output Stream
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
//            System.out.println("got InputStream");

            System.out.println("streams initialized..");
            //create new thread for every client
            ClientHandler clientHandler = new ClientHandler(socket,"client_"+clientCounter,  objectInputStream, objectOutputStream);

            Thread thread = new Thread(clientHandler);
            System.out.println("new thread created for client " + "client_"+clientCounter);
            clientList.add(clientHandler);
            for (ClientHandler c : clientList) {
                System.out.println(c.getName());
            }
            thread.start();
//            System.out.println("now ok");

            clientCounter++;


        }
    }
}

class  ClientHandler implements Runnable {

    Scanner scn = new Scanner(System.in);

    private  String name;
    private  Socket socket;
    int flag ;
    final ObjectOutputStream dataOutputStream;
    final ObjectInputStream dataInputStream;
    boolean isLoggedIn;
    private Cipher serverDecryptCiph;
    private Cipher serverEncryptCiph;

    private Cipher keyDecipher;
    private SecretKey AESKey;
    static String IV = "AAAAAAAAAAAAAAAA";


    public ClientHandler(Socket socket, String name, ObjectInputStream dataInputStream, ObjectOutputStream dataOutputStream) throws IOException {
        this.socket = socket;
        this.dataInputStream  = dataInputStream;
        this.dataOutputStream = dataOutputStream;
        this.name = name;
        this.isLoggedIn = true;
        this.flag = 0;
        System.out.println("client handler initiated for "+ this.name);

    }
    public String getName() {
        return name;
    }


    @Override
    public void run() {
        // message from client
        String received = null;

        Message rcvdmsg = null;
        while (true) {
//            System.out.println(" i m in clientHandler thread..");
            try {
                //Read message from client
//                received = dataInputStream.readUTF();
//                System.out.println(received);
                System.out.println("Listening for msg");

                rcvdmsg = (Message) dataInputStream.readObject();

                if (flag ==0){
                    if (rcvdmsg.getData() != null){
                        decryptAESKey(rcvdmsg.getData());
                        flag++;
                    }
                    else {
                        System.out.println("AES key not received");
                        System.exit(1);
                    }
                }
                else {
                    if (rcvdmsg.getData() != null) {
                        try {

                            received = decryptMessage(rcvdmsg.getData());
                        } catch (Exception e) {
                            System.out.println("Error decrypting" + e.getMessage());
                        }
                    }
                    assert received != null;
                    if (received.equals("logout")) {
                        System.out.println("Client " + this.name + " logged out");
                        isLoggedIn = false;
                        this.socket.close();

                        break;

                    }

                    //See if client wants to logout
//                assert received != null;
//                if(received.equals("logout")){
//                    System.out.println("Client " + this.name + " logged out");
//                    isLoggedIn = false;
//                    this.socket.close();
//
//                    break;
//
//                }

                    //process the message
                    StringTokenizer stringTokenizer = new StringTokenizer(received, ":");
                    String msg = stringTokenizer.nextToken();
                    String sendTo = stringTokenizer.nextToken();
                    System.out.println("After decryption:::: " + "destination:" + sendTo + "> message: " + msg);

                    //search the sendTo in the clientList
                    for (ClientHandler client : Server.clientList) {
                        if (client.getName().equalsIgnoreCase(sendTo)) {
                            System.out.println("Client found..");
                            System.out.println("Client Name:"+client.getName());
                            System.out.println();
//                        client.dataOutputStream.writeUTF(this.name + ": " + msg);
                            String finalMsg = this.name + ": " + msg;

                            try {
                                write(new Message(encryptMessage(finalMsg)),client.dataOutputStream);
                            } catch (Exception e) {
                                System.out.println("Error at encrypting: " + e.getMessage());
                            }
                            break;
                        }
                        else {
                            System.out.println("Not found");
                            System.out.println("client_name:"+ client.getName()+", loginStatus: " + client.isLoggedIn);
                        }
                    }
                }

            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }

        try {
            this.dataOutputStream.close();
            this.dataInputStream.close();
        }
        catch (IOException e) {
            e.printStackTrace();

        }
    }
    public synchronized void write(Message msg, ObjectOutputStream objectOutputStream){
        try {
            System.out.println("writing on stream");
            objectOutputStream.writeObject(msg);
            objectOutputStream.reset();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }



    private void decryptAESKey(byte[] encryptedKey){
        SecretKey key = null;
        PrivateKey privateKey = null;
         keyDecipher = null;

        try{
            privateKey = readPrivateKeyFromFile("private.key");
            keyDecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            keyDecipher.init(Cipher.DECRYPT_MODE, privateKey);
            key = new SecretKeySpec(keyDecipher.doFinal(encryptedKey),"AES");
            flag = 1;
            AESKey = key;

        }
        catch (Exception e){
            e.printStackTrace();
            System.out.println ( "exception decrypting the aes key: "  + e.getMessage() );
        }



    }

    private PrivateKey readPrivateKeyFromFile(String file) throws IOException {

        try (ObjectInputStream readObj = new ObjectInputStream(new BufferedInputStream(new FileInputStream(file)))) {
            BigInteger mod = (BigInteger) readObj.readObject();
            BigInteger exp = (BigInteger) readObj.readObject();

            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod, exp);
            KeyFactory factory = KeyFactory.getInstance("RSA");

            return factory.generatePrivate(keySpec);


        } catch (Exception e) {
            throw new RuntimeException("Some error in reading private key", e);
        }

    }

    private String decryptMessage(byte[] encryptedMessage) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
         serverDecryptCiph = Cipher.getInstance("AES/CBC/PKCS5PADDING");
         serverDecryptCiph.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(IV.getBytes()));

         byte[] msg  = serverDecryptCiph.doFinal(encryptedMessage);

         return new String(msg);
    }

    private byte[] encryptMessage(String msg) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        serverEncryptCiph = null;
        byte[] ciphertext = null;

        serverEncryptCiph = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        serverEncryptCiph.init(Cipher.ENCRYPT_MODE, AESKey, new IvParameterSpec(IV.getBytes()));
        ciphertext = serverEncryptCiph.doFinal(msg.getBytes());

        return ciphertext;
    }
}