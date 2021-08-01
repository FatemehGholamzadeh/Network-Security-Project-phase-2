package ir.aut;

import java.io.*;
import java.math.BigDecimal;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;

import static ir.aut.Server.receiveRequest;

public class Server {
    private static String privateKey = "8877665544332211";
    private static byte[] IV = new byte[16];
    private static byte[] sessionKey = new byte[16];
    private static byte[] pureSessionKey = new byte[16];
    private static AES aes = new AES();
    private static String publicKey = "";
    private static String session_key = "";
    private static byte[] newSessionKey = new byte[7];
    private static byte[] sendBytes = new byte[23];
    private static boolean aBoolean = false;
    public static HashMap<Integer, String> serverKeys = new HashMap<Integer, String>();
    public static int clintNo = 3;


    public static void main(String[] args) throws Exception {

        //initialize IV
        for (int i = 0; i < 16; i++) {
            IV[i] = 0;
        }

        //timer to update session key
        class Hello extends TimerTask {
            public void run() {
                aBoolean = true;
            }
        }
        Timer timer = new Timer();
        timer.schedule(new Hello(), 1000, 1000);//1 Min

        //creating object from RSA
        RSA rsa = new RSA();

        //generating private and public keys
//        keyProducer();

        //create Socket
        ServerSocket serverSocket = new ServerSocket(1234);
        Socket s = serverSocket.accept();

        //dis & dos
        DataInputStream dis = new DataInputStream(s.getInputStream());
        DataOutputStream dos = new DataOutputStream(s.getOutputStream());

        //receiving Request
        String userName = receiveRequest(dis);

        //find public key for user
        find_public_key(userName);


        //creating session key
        sessionKey = createSessionKey(publicKey, rsa);
        session_key=Base64.getEncoder().encodeToString(sessionKey);
        dos.writeUTF(session_key);

        //instance of messageDigest
        MessageDigest digest = MessageDigest.getInstance("SHA-256");



        //sending file
        File f = new File("5.txt");
        BigDecimal bytes = new BigDecimal(f.length());
        int size = bytes.intValue();
        byte[] buffer = new byte[16];
        FileInputStream inputStream = new FileInputStream(f);
        dos.writeInt(size);

        String response ;


        for (int i = 0; i < (size / 16 + 1); i++) {

            if (aBoolean) {
                dos.writeUTF("session");
                sessionKey = createSessionKey(publicKey, rsa);
                session_key=Base64.getEncoder().encodeToString(sessionKey);
                dos.writeUTF(session_key);
                aBoolean = false;
            }
            inputStream.read(buffer);
            byte[] hash = digest.digest(buffer);


            byte[] c = new byte[buffer.length + hash.length];
            System.arraycopy(buffer, 0, c, 0, buffer.length);
            System.arraycopy(hash, 0, c, buffer.length, hash.length);

            //buffer = aes.encrypt(buffer,pureSessionKey,IV);
           // hash =aes.encrypt(hash,pureSessionKey,IV);
            byte[] encrypted_c =aes.encrypt(c,pureSessionKey,IV);
            dos.writeUTF(Base64.getEncoder().encodeToString(encrypted_c));
            response = dis.readUTF();
            if (response.equals("error")){
                dos.writeUTF(Base64.getEncoder().encodeToString(encrypted_c));
            }
            System.out.println(Base64.getEncoder().encodeToString(encrypted_c));


        }



    }







    public static void find_public_key(String id) throws Exception {
        File file = new File("RSA/serverKeys.txt");
        FileReader fr = new FileReader(file);   //reads the file
        BufferedReader br = new BufferedReader(fr);  //creates a buffering character input stream
        StringBuffer sb = new StringBuffer();    //constructs a string buffer with no characters
        String line;
        while ((line = br.readLine()) != null) {
            String[] strarr = line.split(",");
            if (strarr[0].equals(id)) {
                publicKey = strarr[1];
            }
        }
        fr.close();

    }


    public static byte[] createSessionKey(String physicalKey, RSA rsa) throws Exception {

        //ciphering a random string with physical key
        String randomString = randomString(16);
        byte[] sessionKey = rsa.encrypt(randomString, publicKey);
        pureSessionKey = randomString.getBytes();
        return sessionKey;

    }

    public static String randomString(int n) {
        {
            // chose a Character random from this String
            String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    + "0123456789"
                    + "abcdefghijklmnopqrstuvxyz";

            // create StringBuffer size of AlphaNumericString
            StringBuilder sb = new StringBuilder(n);

            for (int i = 0; i < n; i++) {

                // generate a random number between
                // 0 to AlphaNumericString variable length
                int index
                        = (int) (AlphaNumericString.length()
                        * Math.random());

                // add Character one by one in end of sb
                sb.append(AlphaNumericString
                        .charAt(index));
            }

            return sb.toString();
        }
    }

    public static String receiveRequest(DataInputStream dis) throws Exception {
        String userName = dis.readUTF();
        System.out.println("we have a Request from USer with this ID : ");
        System.out.println(userName);
        return userName;
    }


    public static void keyProducer() throws Exception {
        KeyGenerator keyGenerator1 = new KeyGenerator();
        for (int i = 0; i < clintNo; i++) {
            KeyGenerator keyGenerator = new KeyGenerator();
            keyGenerator.getPublicKey();
            serverKeys.put(i, Base64.getEncoder().encodeToString(keyGenerator.getPublicKey().getEncoded()));
            keyGenerator.writeToFile("RSA/client" + i + ".txt", Base64.getEncoder().encodeToString(keyGenerator.getPrivateKey().getEncoded()));

        }

        File fout = new File("RSA/serverKeys.txt");
        FileOutputStream fos = new FileOutputStream(fout);

        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos));

        for (int i = 0; i < clintNo; i++) {
            bw.write(i + "," + serverKeys.get(i));
            bw.newLine();
        }

        bw.close();

    }


} 