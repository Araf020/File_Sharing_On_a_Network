package com.arafat.filemanager;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class FileManager {
    //complete it for file
    String fileLocation;

    public FileManager(String fileLocation){
        this.fileLocation = fileLocation;
    }

    public String getFileLocation(){
        return fileLocation;
    }

    public void setFileLocation(String fileLocation){
        this.fileLocation = fileLocation;
    }


    public byte[] readFile(){
        byte[] buffer = null;
        try{
            FileInputStream fileInputStream = new FileInputStream(fileLocation);
            buffer = new byte[fileInputStream.available()];
            fileInputStream.read(buffer);
            fileInputStream.close();
            System.out.println(new String(buffer));
            return buffer;
        }catch(Exception e){
            e.printStackTrace();
        }
        return buffer;
    }

    public void writeFile(String text){
        try{
            FileInputStream fileInputStream = new FileInputStream(fileLocation);
            byte[] buffer = new byte[fileInputStream.available()];
            fileInputStream.read(buffer);
            fileInputStream.close();
            System.out.println(new String(buffer));
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public FileInputStream getFileStream(){
        try {
            return new FileInputStream(fileLocation);
        }
        catch (Exception e){
            System.out.println("File not found: "+e.getMessage());
            return null;
        }
    }

    public static void copyFile(InputStream in, OutputStream out){

           byte[] buffer = new byte[1024];
           int len;
           try{
               while((len = in.read(buffer)) != -1){
                        out.write(buffer, 0, len);
               }
           }
           catch(Exception e){
                    e.printStackTrace();
           }
    }






}
