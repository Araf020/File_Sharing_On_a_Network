package com.arafat.security;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RSA {
    Key publicKey;
    Key privateKey;



    public void createRSA() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        /*
        *generate public and private key pair*
        *
        * */

        keyPairGenerator.initialize(1024);
        KeyPair kpair = keyPairGenerator.generateKeyPair();
        publicKey = kpair.getPublic();
        privateKey = kpair.getPrivate();

        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = factory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeySpec = factory.getKeySpec(privateKey,RSAPrivateKeySpec.class);


        seriaLizeFile("public.key", publicKeySpec.getModulus(),publicKeySpec.getPublicExponent());
        seriaLizeFile("private.key", privateKeySpec.getModulus(),privateKeySpec.getPrivateExponent());


        System.out.println("Rsa created.. leaving..");
    }

    private void seriaLizeFile(String file, BigInteger modulus, BigInteger publicExponent) throws IOException {

        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(file)))) {

            objectOutputStream.writeObject(modulus);
            objectOutputStream.writeObject(publicExponent);
            System.out.println("Key File Created : " + file);
        } catch (Exception e) {
            throw new IOException("Error while writing key object", e);
        }

    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        System.out.println("Instantiate a RSA class");

        RSA rsa = new RSA();

        rsa.createRSA();
        System.out.println("Rsa created.. leaving..");
    }


}
