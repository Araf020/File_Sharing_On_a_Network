package com.arafat.client;
//
//// Message format is:
//// Message : recipient
////here's also another Message handler works to deliver the Message to the recipient
//
//import com.arafat.Message.Message;
//
//import javax.crypto.*;
//import javax.crypto.spec.IvParameterSpec;
//import java.io.*;
//import java.math.BigInteger;
//import java.net.InetAddress;
//import java.net.Socket;
//import java.security.*;
//import java.security.spec.RSAPublicKeySpec;
//import java.util.Scanner;
//
////Message format : msg:clientName
//
//public class Client {
//
//    final static int serverPort = 9090;
//    private int port;
//    private Socket socket;
//    private InetAddress server;
//    private Cipher cipher_1;
//    private Cipher cipher_2;
//    private SecretKey AESkey;
//    static String IV = "AAAAAAAAAAAAAAAA";
//    public int flag = 0;
//    public ObjectInputStream objectInputStream;
//    public ObjectOutputStream objectOutputStream;
//
//    public Client(InetAddress server, int port){
//        this.server = server;
//        this.port = port;
//    }
//
//    public  void initialize() throws IOException {
//
//       //request connection to the server
//       socket = new Socket(server,port);
//       System.out.println("connection accepted at "+ socket.getInetAddress() + " :"+socket.getPort() );
//
//       //initialize the streams
//        objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
//        objectInputStream = new ObjectInputStream(socket.getInputStream());
//
//        System.out.println("client streams initialized...");
//       //start both the threads
//        new sendMessage().start();
//        new receiveMessage().start();
//        System.out.println("client resources initialized...");
//
//    }
//
//    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
//
//        //get the localhost Ip
//        InetAddress inetAddress = InetAddress.getByName("localhost");
//        Client client = new Client(inetAddress,serverPort);
//        //set the AESKey
//        client.generateAESKey();
//        //start the client side
//        client.initialize();
//
//
//
//    }
//
//
//    //AES key will be used by server and client to encrypt / decrypt Message
//
//    private void generateAESKey() throws NoSuchAlgorithmException {
//        AESkey = null;
//        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//        keyGenerator.init(128);
//        this.AESkey = keyGenerator.generateKey();
//        System.out.println("Generated AESKey:" + AESkey);
//
//
//    }
//
//    private byte[] encryptAESKey() {
//
//        cipher_1 = null;
//        byte[] key = null;
//
//        try {
//
//            //get the public key created by RSA keyPair generator
//
//            PublicKey publicKey = readPublicKeyFromFile("public.key");
//            if (publicKey !=null)
//                System.out.println("public key is not null");
//            System.out.println("AES key is under process of encryption");
//
//            //creating cipher with the client's public key
//            cipher_1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//            cipher_1.init(Cipher.ENCRYPT_MODE, publicKey);
//
//            long time_1 = System.nanoTime();
//            //encode the key
//            key = cipher_1.doFinal(AESkey.getEncoded());
//
//            long time_2 = System.nanoTime();
//            long totalRSATime = time_2 - time_1;
//            System.out.println("Time taken by Encryption: " + totalRSATime + " nano second");
//
//            flag = 1;
//        } catch (Exception e) {
//            System.out.println("exception encoding the key" + e.getMessage());
//            e.printStackTrace();
//        }
//
//        //return the key
//        return key;
//    }
//
//    private PublicKey readPublicKeyFromFile(String file) throws IOException {
//
//        try (ObjectInputStream inputStream = new ObjectInputStream(new BufferedInputStream(new FileInputStream(file)))) {
//            BigInteger modulus = (BigInteger) inputStream.readObject();
//            BigInteger exponent = (BigInteger) inputStream.readObject();
//
//            RSAPublicKeySpec keySpec = new
//                    RSAPublicKeySpec(modulus, exponent);
//
//            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//
//            return keyFactory.generatePublic(keySpec);
//        } catch (Exception e) {
//            System.out.println("error in reading public key " + e.getMessage());
//            return null;
//        }
//
//    }
//
//    private byte[] encryptMessage(String Message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//
//        byte[] cipherText = null;
//        cipher_2 = null;
//        cipher_2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
//        cipher_2.init(Cipher.ENCRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()));
//
//        cipherText = cipher_2.doFinal(Message.getBytes());
//
//        return cipherText;
//    }
//
//    private void decryptMessage(byte[] encryptedMessage) {
//        System.out.println("decrypting the Message....");
//        cipher_2 = null;
//        byte[] msg = null;
//
//        try {
//            cipher_2 = Cipher.getInstance("AES");
//            //initializing decryption
//            cipher_2.init(Cipher.DECRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()));
//
//            msg = cipher_2.doFinal(encryptedMessage);
//            System.out.println("Client : Incoming Message: " + new String(msg));
//            System.out.println("Client: Enter outgoing Message: ");
//
//        } catch (Exception e) {
//            System.out.println("Error in decrypting the Message: " + e.getMessage());
//        }
//
//
//    }
//
//        /*Inner class for sending  and receiving Message*/
//    class sendMessage extends Thread {
//        @Override
//        public void run() {
//
//            while (true) {
//
//                try {
//                    //if flag = 0 then send the AES key.
//                    Message toSend;
//                    if (flag==0) {
//
//                        toSend = new Message(encryptAESKey());
//                        objectOutputStream.writeObject(toSend);
//                        flag =1;
//
//                    } else {
//                        Scanner scanner = new Scanner(System.in);
//                        System.out.println("Type Message:(msg:clientName) ");
//                        //Message format==> msg:clientName
//                        String Message = scanner.nextLine();
//                        System.out.println(Message);
//                        //encrypting the Message
//                        toSend = new Message(encryptMessage(Message));
//                        //sending encrypted Message
//                        objectOutputStream.writeObject(toSend);
//
//                    }
//
//                } catch (Exception e) {
//                    System.out.println("error at sending" + e.getMessage());
//                    break;
//                }
//            }
//        }
//    }
//
//    class receiveMessage extends Thread {
//        public void run(){
//
//            while (true){
//                try
//                {
//                    //receiving the Message
//                    System.out.println("reading encrypted Message from stream");
//                    Message receivedMsg = (Message) objectInputStream.readObject();
//                    //decrypting the Message
//                    decryptMessage(receivedMsg.getData());
//                }
//                catch (Exception e){
//                    System.out.println("error at receiving msg: "+ e.getMessage());
//
//                }
//            }
//        }
//    }
//}


/**
 * Client.java
 *
 *  Dependency : Sever.java, Message.java, RSA.java
 *
 *  Run Client only after running the Server program.
 *
 * Compile	 	$javac Client.java
 * Run 			$java Client
 *
 *  References:
 *  http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html
 *  http://www.javamex.com/tutorials/cryptography/rsa_encryption.shtml
 *
 */


import com.arafat.message.Message;
import com.arafat.server.DataPack;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

//import java.math.BigInteger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.Data;

/*
 *
 * Public class Client.
 *
 *  The Client will send encrypted Message to the server.
 *
 *  First Message sent to server is the AES key.
 *fA
 *  After that client will ask for input. The provided input will be encrypted using the AES key and will be send to server.
 *
 *
 */

public class Client {

    private ObjectOutputStream sOutput;
    private ObjectInputStream sInput;

    private Socket socket;
    private String server;
    private int port;
    private Cipher cipher1;
    private Cipher cipher2;
    int i = 0;
    int flag_1 = 0;
    Message m;
    SecretKey AESkey;
    SecretKey listeningAESkey;
    Message toSend;
    static String IV = "AAAAAAAAAAAAAAAA";



    // ===== THE CONSTRUCTOR ==========

    Client (String server, int port){
        this.server = server;
        this.port = port;
    }



    /*
     *
     * The main method
     *
     * Creates the an instance of Client class with provided server address and TCP port to establish the socket conenction.
     *
     * @param
     * 			Command Line arguments.
     *
     * Program Flow :
     *
     * 		MAIN --> start() & getKey()
     * 		start() ---> sendToServer Thread
     * 		sendToServer Thread ---> EncryptSecretKey() or encryptData(string)
     *
     *
     */


    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        String serverAddress;

        int portNumber = 9090;
        if(args.length < 1){
            System.out.println("#############################################################");
            System.out.println("# 															 ");
            System.out.println("# Usage: $ java Client [sever ip]							 ");
            System.out.println("# 															 ");
            System.out.println("# e.g. $ java Client 192.168.1.1																 ");
            System.out.println("# 							 								 ");
            System.out.println("# NO ARGUMENT REQUIRED IF SERVER RUNNING ON LOCALHOST		 ");
            System.out.println("# 															 ");
            System.out.println("#############################################################");

            serverAddress = "localhost";
        }
        else{
            serverAddress = args[0];
        }
        Client client = new Client(serverAddress, portNumber);
        client.generateAESkey();
        client.start();
    }

    /*
     * the start method.
     * 				establishes a socket connection with the server.
     *
     *
     */

    void start() throws IOException{
        socket = new Socket(server, port);
        System.out.println("connection accepted " + socket.getInetAddress() + " :"  + socket.getPort());


        sInput = new ObjectInputStream(socket.getInputStream());
        sOutput = new ObjectOutputStream(socket.getOutputStream());

        new sendToServer().start();
        new listenFromServer().start();
    }



    /*
     *
     *  listenFromServer method.
     *  						Will receive the Message from server and call the decryption method.
     *
     *
     */



    class listenFromServer extends Thread {
        public void run(){
            while(true){
                try{
                    //read dataPack which consists of Message and AesKey
                    DataPack dataPack = (DataPack) sInput.readObject();

                    //set the aesKey needed
                    decryptAESKey(dataPack.getAesKey());
                    //decrypt the message
                    decryptMessage(dataPack.getMessage());
//                    m = (Message) sInput.readObject();


//                    if (flag_1 == 0){
//                        if (m != null) {
//                            decryptAESKey(m.getData());
//                            flag_1 = 1;
//                        }
//                        else
//                            System.out.println("no AES key sent!");
//                    }
//                    else {
//                        decryptMessage(m.getData());
//                    }
                } catch (Exception e){
                    e.printStackTrace();
                    System.out.println("connection closed");
                }
            }
        }
    }



    /*
     * sendToServer Class. Extends the thread class. Runs continuously.
     *
     * 						Will send encrypted Messages to the server.
     * 						The first Message sent to server will be encrypted AES key. The same key will be used by server to decrypt the future Messages.
     *
     * 						Once the AES key is shared, the client Will accept console inputs and encrypt it before sending to server.
     *
     *
     */


    class sendToServer extends Thread {
        public void run(){
            while(true){
                try{

                    if (i == 0){
                        toSend = null;

                        toSend = new Message(encryptAESKey());
                        sOutput.writeObject(toSend);
                        i =1;
                    }

                    else{

                        System.out.println("CLIENT: Enter OUTGOING Message > ");
                        Scanner sc = new Scanner(System.in);
                        String s = sc.nextLine();
                        toSend = new Message(encryptMessage(s));
                        sOutput.writeObject(toSend);
                    }

                } catch (Exception e){
                    e.printStackTrace();
                    System.out.println("No Message sent to server");
                    break;
                }
            }
        }
    }


    /*
     * //============== Create AES Key =================================
     *
     * generateAESkey method
     *
     * 						Called by main method, generates the AES key for encryption / decryption of the Messages exchanged between client and server.
     */

    void generateAESkey() throws NoSuchAlgorithmException{
        AESkey = null;
        KeyGenerator Gen = KeyGenerator.getInstance("AES");
        Gen.init(128);
        AESkey = Gen.generateKey();
        System.out.println("Genereated the AES key : " + AESkey);
    }



    /*
     * // ====== Read RSA Public key to Encrypt the AES key  ==================
     *
     * encryptAESKey method.
     *
     * 						Will encrypt the AES key generated by generateAESkey method. It will also calculate the time taken for encrypting the AES key using RSA encryption method.
     *
     * 						To encrypt the AES key, this method will read RSA public key from the RSA public = private key pairs saved in the same directory.
     *
     * 						Dependency: the public key  file "public.key" should be saved in the same directory. (Performed by server.java class)
     *
     */

    private void decryptAESKey(byte[] encryptedKey){
        SecretKey key = null;
        PrivateKey privateKey = null;
        Cipher keyDecipher = null;

        try{
            privateKey = readPrivateKeyFromFile("private.key");
            keyDecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            keyDecipher.init(Cipher.DECRYPT_MODE, privateKey);
            key = new SecretKeySpec(keyDecipher.doFinal(encryptedKey),"AES");
            flag_1 = 1;
            this.listeningAESkey = key;

        }
        catch (Exception e){
            e.printStackTrace();
            System.out.println ( "exception decrypting the aes key: "  + e.getMessage() );
        }



    }

    private byte[] encryptAESKey (){
        cipher1 = null;
        byte[] key = null;
        try
        {
            PublicKey pK = readPublicKeyFromFile("public.key");
            System.out.println("Encrypting the AES key using RSA Public Key" + pK);
            // initialize the cipher with the user's public key
            cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            cipher1.init(Cipher.ENCRYPT_MODE, pK );
            long time1 = System.nanoTime();
            key = cipher1.doFinal(AESkey.getEncoded());   // this encrypted key will be sent to the server.
            long time2 = System.nanoTime();
            long totalRSA = time2 - time1;
            System.out.println("Time taken by RSA Encryption (Nano Seconds) : " + totalRSA);
            i = 1;
        }

        catch(Exception e ) {
            System.out.println ( "exception encoding key: " + e.getMessage() );
            e.printStackTrace();
        }
        return key;
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


    /*
     * //============= Encrypt Data to send =================
     *
     * encryptMessage method
     * 						Encrypts the string input using AES encryption with AES key generated by generateAESkey method.
     *
     * @param 	String s
     * 					Input string to encrypt
     *
     * Returns byte array as output.
     *
     */


    private byte[] encryptMessage(String s) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException{
        cipher2 = null;
        byte[] cipherText = null;
        cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        cipher2.init(Cipher.ENCRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()) );
        long time3 = System.nanoTime();
        cipherText = cipher2.doFinal(s.getBytes());
        long time4 = System.nanoTime();
        long totalAES = time4 - time3;
        System.out.println("Time taken by AES Encryption (Nano Seconds) " + totalAES);
        return cipherText;
    }


    /*
     * //=========== Decipher the received Message with AES key =================
     *
     * decryptMessage method, will decrypt the cipher text received from server. Currently disabled, can be enabled for two way communication.
     *
     * @param byte[] data
     * 					takes the byte array of encrypted Message as input. Returns plain text.
     *
     *
     */


    private void decryptMessage(byte[] encryptedMessage) {
        cipher2 = null;
        try
        {
            cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher2.init(Cipher.DECRYPT_MODE, listeningAESkey, new IvParameterSpec(IV.getBytes()));
            byte[] msg = cipher2.doFinal(encryptedMessage);
            System.out.println("CLIENT: INCOMING Message From Server   >> " + new String(msg));
            System.out.println("CLIENT: Enter OUTGOING Message > ");
        }

        catch(Exception e)
        {
            e.getCause();
            e.printStackTrace();
            System.out.println ( "Exception genereated in decryptData method. Exception Name  :"  + e.getMessage() );
        }
    }



    /*
     * closeSocket method  	//============== To close all the sockets and streams.===================
     * 						Closes the input/output streams and sockets.
     *
     *
     */


    public void closeSocket() {
        try{
            if(sInput !=null) sInput.close();
            if(sOutput !=null) sOutput.close();
            if(socket !=null) socket.close();
        }catch (IOException ioe){
            System.out.println("Error in Disconnect methd");
        }
    }


    /*
     *  // ===================== Reading RSA public key from  file ===============
     *
     * readPublicKeyFromFile method.
     *
     * 								Will read the RSA public key from the file "public.key"
     * 								on the same directory to encrypt the AES key.
     *
     */



    PublicKey readPublicKeyFromFile(String fileName) throws IOException {

        FileInputStream in = new FileInputStream(fileName);
        ObjectInputStream oin =  new ObjectInputStream(new BufferedInputStream(in));

        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPublicKeySpec keySpecifications = new RSAPublicKeySpec(m, e);

            KeyFactory kF = KeyFactory.getInstance("RSA");
            PublicKey pubK = kF.generatePublic(keySpecifications);
            return pubK;
        } catch (Exception e) {
            throw new RuntimeException("Some error in reading public key", e);
        } finally {
            oin.close();
        }
    }

}



