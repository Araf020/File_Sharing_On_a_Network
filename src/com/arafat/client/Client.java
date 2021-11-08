package com.arafat.client;

// message format is:
// message : recipient
//here's also another message handler works to deliver the message to the recipient

import com.arafat.message.Message;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

//message format : msg:clientName

public class Client {

    final static int serverPort = 9090;
    private int port;
    private Socket socket;
    private InetAddress server;
    private Cipher cipher_1;
    private Cipher cipher_2;
    private SecretKey AESkey;
    static String IV = "AAAAAAAAAAAAAAAA";
    public int flag = 0;
    public ObjectInputStream objectInputStream;
    public ObjectOutputStream objectOutputStream;

    public Client(InetAddress server, int port){
        this.server = server;
        this.port = port;
    }

    public  void initialize() throws IOException {

       //request connection to the server
       socket = new Socket(server,port);
       System.out.println("connection accepted at "+ socket.getInetAddress() + " :"+socket.getPort() );

       //initialize the streams
        objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        objectInputStream = new ObjectInputStream(socket.getInputStream());

        System.out.println("client streams initialized...");
       //start both the threads
        new sendMessage().start();
        new receiveMessage().start();
        System.out.println("client resources initialized...");

    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        //get the localhost Ip
        InetAddress inetAddress = InetAddress.getByName("localhost");
        Client client = new Client(inetAddress,serverPort);
        //set the AESKey
        client.generateAESKey();
        //start the client side
        client.initialize();



    }


    //AES key will be used by server and client to encrypt / decrypt message

    private void generateAESKey() throws NoSuchAlgorithmException {
        AESkey = null;
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        this.AESkey = keyGenerator.generateKey();
        System.out.println("Generated AESKey:" + AESkey);


    }

    private byte[] encryptAESKey() {

        cipher_1 = null;
        byte[] key = null;

        try {

            //get the public key created by RSA keyPair generator

            PublicKey publicKey = readPublicKeyFromFile("public.key");
            if (publicKey !=null)
                System.out.println("public key is not null");
            System.out.println("AES key is under process of encryption");

            //creating cipher with the client's public key
            cipher_1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher_1.init(Cipher.ENCRYPT_MODE, publicKey);

            long time_1 = System.nanoTime();
            //encode the key
            key = cipher_1.doFinal(AESkey.getEncoded());

            long time_2 = System.nanoTime();
            long totalRSATime = time_2 - time_1;
            System.out.println("Time taken by Encryption: " + totalRSATime + " nano second");

            flag = 1;
        } catch (Exception e) {
            System.out.println("exception encoding the key" + e.getMessage());
            e.printStackTrace();
        }

        //return the key
        return key;
    }

    private PublicKey readPublicKeyFromFile(String file) throws IOException {

        try (ObjectInputStream inputStream = new ObjectInputStream(new BufferedInputStream(new FileInputStream(file)))) {
            BigInteger modulus = (BigInteger) inputStream.readObject();
            BigInteger exponent = (BigInteger) inputStream.readObject();

            RSAPublicKeySpec keySpec = new
                    RSAPublicKeySpec(modulus, exponent);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            System.out.println("error in reading public key " + e.getMessage());
            return null;
        }

    }

    private byte[] encryptMessage(String message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        byte[] cipherText = null;
        cipher_2 = null;
        cipher_2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher_2.init(Cipher.ENCRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()));

        cipherText = cipher_2.doFinal(message.getBytes());

        return cipherText;
    }

    private void decryptMessage(byte[] encryptedMessage) {
        System.out.println("decrypting the message....");
        cipher_2 = null;
        byte[] msg = null;

        try {
            cipher_2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //initializing decryption
            cipher_2.init(Cipher.DECRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()));

            msg = cipher_2.doFinal(encryptedMessage);
            System.out.println("Client : Incoming message: " + new String(msg));
            System.out.println("Client: Enter outgoing message: ");

        } catch (Exception e) {
            System.out.println("Error in decrypting the message: " + e.getMessage());
        }


    }

        /*Inner class for sending  and receiving message*/
    class sendMessage extends Thread {
        @Override
        public void run() {

            while (true) {

                try {
                    //if flag = 0 then send the AES key.
                    Message toSend;
                    if (flag==0) {

                        toSend = new Message(encryptAESKey());
                        objectOutputStream.writeObject(toSend);
                        flag =1;

                    } else {
                        Scanner scanner = new Scanner(System.in);
                        System.out.println("Type message:(msg:clientName) ");
                        //message format==> msg:clientName
                        String message = scanner.nextLine();
                        System.out.println(message);
                        //encrypting the message
                        toSend = new Message(encryptMessage(message));
                        //sending encrypted message
                        objectOutputStream.writeObject(toSend);

                    }

                } catch (Exception e) {
                    System.out.println("error at sending" + e.getMessage());
                    break;
                }
            }
        }
    }

    class receiveMessage extends Thread {
        public void run(){

            while (true){
                try
                {
                    //receiving the message
                    System.out.println("reading encrypted message from stream");
                    Message receivedMsg = (Message) objectInputStream.readObject();
                    //decrypting the message
                    decryptMessage(receivedMsg.getData());
                }
                catch (Exception e){
                    System.out.println("error at receiving msg: "+ e.getMessage());

                }
            }
        }
    }
}