package ir.aut;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    private static byte[] sessionKey = new byte[16];
    private static String privateKey = "";
    private static byte[] IV = new byte[16];
    private static byte[] sk = new byte[16];
    private static String session_key = "";


    public static void main(String[] args) throws Exception {

        //initialize IV
        for (int i = 0; i < 16; i++) {
            IV[i] = 0;
        }

        //create AES object
        AES aes = new AES();

        //create RSA object
        RSA rsa = new RSA();

        //defining IP and port
       // InetAddress ip = InetAddress.getLocalHost();
        int port = 1234;

        //defining Socket
        Socket s = new Socket("192.168.43.32", port);

        //dos and dis
        DataInputStream dis = new DataInputStream(s.getInputStream());
        DataOutputStream dos = new DataOutputStream(s.getOutputStream());

        //sending Request
        sendRequest(dos);

        //read private key
        read_private_key("client1");

        //read session key bare avval
        String encrypted_session_key = dis.readUTF();


        //decrypting encrypted_session_key
        session_key = rsa.decrypt(encrypted_session_key, privateKey);

        //instance of messageDigest
        MessageDigest digest = MessageDigest.getInstance("SHA-256");


        // read length of incoming message
        int length = dis.readInt();

        FileOutputStream out = new FileOutputStream(new File("D:\\download\\3.jpg"), false);
        //byte[] message = new byte[16];
        String message ="";
        byte[] results;
        for (int i = 0; i < (length / 16 + 1 ); i++) {
          //  dis.read(message);
            message = dis.readUTF();
            if (message.contains("session")) {
                System.out.println("session key changed ! ");
                encrypted_session_key = dis.readUTF();
                session_key = rsa.decrypt(encrypted_session_key, privateKey);
                message = dis.readUTF();

            }

            byte[] bytes = Base64.getDecoder().decode(message);
            byte[] s3 = session_key.getBytes();

            results = aes.decrypt(bytes,s3,IV);
            byte[] first =new byte[16];
            byte[] second=new byte[32] ;
            for (int j = 0; j < 16; j++) {
                first[j] = results[j];
            }
            for (int j = 16; j <results.length ; j++) {
                second[j-16] = results[j];

            }
            if (Arrays.equals(digest.digest(first),second) ){
                dos.writeUTF("ok");
                out.write(first);
            }
            else if (!Arrays.equals(digest.digest(first),second)){
                dos.writeUTF("error");
                message = dis.readUTF();
                if (message.contains("session")) {
                    System.out.println("session key changed ! ");
                    encrypted_session_key = dis.readUTF();
                    session_key = rsa.decrypt(encrypted_session_key, privateKey);
                    message = dis.readUTF();

                }
                byte[] bytes1 = Base64.getDecoder().decode(message);
                byte[] s31 = session_key.getBytes();
                results = aes.decrypt(bytes1,s31,IV);
                byte[] first1 =new byte[16];
                for (int j = 0; j < 16; j++) {
                    first[j] = results[j];
                }
                out.write(first);



            }



        }
        s.close();


    }

    public static void read_private_key(String fileName) throws Exception {
        File file = new File("RSA/" + fileName + ".txt");
        FileReader fr = new FileReader(file);   //reads the file
        BufferedReader br = new BufferedReader(fr);  //creates a buffering character input stream
        StringBuffer sb = new StringBuffer();    //constructs a string buffer with no characters
        String line;
        while ((line = br.readLine()) != null) {
            privateKey = line;
        }
        fr.close();
    }

    public static void sendRequest(DataOutputStream dos) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("please Enter your ID : ");
        String userName = scanner.nextLine();
        System.out.println("we're sending your ID ... ");
        dos.writeUTF(userName);

    }
}