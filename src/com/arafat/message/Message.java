package com.arafat.message;

import java.io.Serial;
import java.io.Serializable;

public class Message implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;
    byte[] data;

    public Message(byte[] data){
        this.data = data;
    }

    public byte[] getData(){
        return data;
    }



}
