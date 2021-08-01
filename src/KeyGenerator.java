package ir.aut;


import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class KeyGenerator {

    public static HashMap<Integer, String> serverKeys = new HashMap<Integer, String>();
    public static int clintNo = 3 ;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public KeyGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public void writeToFile(String path, String key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key.getBytes());
        fos.flush();
        fos.close();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    public HashMap<Integer,String> getServerKeys(){
        return serverKeys;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        KeyGenerator keyGenerator1 = new KeyGenerator();
        for (int i = 0; i < clintNo; i++) {
            KeyGenerator keyGenerator = new KeyGenerator();
            keyGenerator.getPublicKey();
            serverKeys.put(i, Base64.getEncoder().encodeToString(keyGenerator.getPublicKey().getEncoded()));
            keyGenerator.writeToFile("RSA/client"+i+".txt", Base64.getEncoder().encodeToString(keyGenerator.getPrivateKey().getEncoded()));

        }

            File fout = new File("RSA/serverKeys.txt");
            FileOutputStream fos = new FileOutputStream(fout);

            BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos));

            for (int i = 0; i < clintNo; i++) {
                bw.write(i+"," + serverKeys.get(i));
                bw.newLine();
            }

            bw.close();

    }
}