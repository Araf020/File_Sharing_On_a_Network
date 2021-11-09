package com.arafat.server;

import com.arafat.message.Message;

import java.io.Serial;
import java.io.Serializable;

public class DataPack implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private byte[] aesKey;
    private byte[] message;
    private String messageType;

    public DataPack(byte[] message, byte[] aesKey){
        this.aesKey = aesKey;
        this.message = message;
    }

    public DataPack(byte[] message, byte[] aesKey, String messageType){
        this.aesKey = aesKey;
        this.message = message;
        this.messageType = messageType;
    }



    public String getMessageType() {
        return messageType;
    }

    public byte[] getAesKey(){
        return aesKey;
    }

    public byte[] getMessage(){
        return message;
    }

}
