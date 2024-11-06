package com.uniandes.edu;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class Client {
  private static final String serverPublicKeyPath = "data/key.pub";
  private static PublicKey serverKey;
  private static boolean delegateMode = false;
  private byte[] symmetricCipherKey;
  private byte[] symmetricHMACKey;
  private byte[] iv = new byte[16];

  public static void loadKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    byte[] publicKeyBytes = Files.readAllBytes(Paths.get(serverPublicKeyPath));
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
    serverKey = keyFactory.generatePublic(publicKeySpec);
  }

  public static void start(String id, String packageId) { // Does not matter if it runs delegate or not
    Client client = new Client();
    client.askServer(id, packageId);
  }

  public static void start(int amount) throws InterruptedException {
    Random random = new Random();
    System.out.println(delegateMode);
    if (!delegateMode) {
      Client client = new Client();
      for (int i = 0; i < amount; i++) {
        String userId = "user" + random.nextInt(6);
        String packageId = "p" + random.nextInt(32);
        client.askServer(userId, packageId);
      }
    } else {
      ExecutorService executor = Executors.newFixedThreadPool(amount);
      for (int i = 0; i < amount; i++) {
        String userId = "user" + random.nextInt(6);
        String packageId = "p" + random.nextInt(32);
        executor.submit(() -> {
          Client client = new Client();
          client.askServer(userId, packageId);
          System.out.println(Thread.currentThread().getName() + ": Finished");
        });
      }
      executor.shutdown();
      executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
    }
  }

  private static void setDelegateMode(boolean useDelegateMode) {
    delegateMode = useDelegateMode;
  }

  public static void main(String[] args) throws Exception {
    System.out.println("Cargando llave publica del servidor...");
    Client.loadKeys();

    Scanner scanner = new Scanner(System.in);

    System.out.print("Desea correr el cliente en modo iterativo? (y/n)\n> ");

    Client.setDelegateMode(scanner.next().equalsIgnoreCase("n"));

    System.out.print("Ingrese la cantidad de consultas a envíar.\n Para más de una consulta los datos serán aleatoreos.\n> ");

    int amount = scanner.nextInt();

    if (amount == 1) {
      System.out.println("Por favor ingrese el id de usuario:");
      String userId = scanner.next();
      System.out.println("Por favor ingrese el id de paquete a consultar:");
      String packageId = scanner.next();
      Client.start(userId, packageId);
    } else {
      Client.start(amount);
    }
  }

  private String generateChallenge() {
    byte[] challengeBytes = new byte[32];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(challengeBytes);

    return Base64.getEncoder().encodeToString(challengeBytes);
  }

  private String encryptWithPublicKey(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, serverKey);
    return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
  }

  private boolean isValidServerSignature(byte[] signed, byte[]... arrays) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    int totalLength = 0;
    for (byte[] arr : arrays) {
      totalLength += arr.length;
    }
    byte[] concatenated = new byte[totalLength];
    int offset = 0;
    for (byte[] arr : arrays) {
      System.arraycopy(arr, 0, concatenated, offset, arr.length);
      offset += arr.length;
    }

    Signature signature = Signature.getInstance("SHA1withRSA");
    signature.initVerify(serverKey);
    signature.update(concatenated);
    return signature.verify(signed);
  }

  private BigInteger generatePrivateSymmetricKey(BigInteger p) {
    SecureRandom random = new SecureRandom();
    return new BigInteger(1024, random).mod(p.subtract(BigInteger.ONE));
  }

  private void doChallenge(PrintWriter writer, BufferedReader reader) throws Exception {
    String challenge = generateChallenge();
    String encrypted = encryptWithPublicKey(challenge);

    writer.println(encrypted);

    String received = reader.readLine();

    if (received.equals(challenge)) {
      writer.println("OK");
    } else {
      writer.println("ERROR");
      throw new Exception("Challenge mismatch");
    }
  }

  private void keyExchange(PrintWriter writer, BufferedReader reader) throws Exception {
    BigInteger g = new BigInteger(reader.readLine());
    BigInteger p = new BigInteger(reader.readLine());
    BigInteger gToTheX = new BigInteger(reader.readLine());

    byte[] signed = Base64.getDecoder().decode(reader.readLine());

    if (isValidServerSignature(signed, g.toByteArray(), p.toByteArray(), gToTheX.toByteArray())) {
      writer.println("OK");
    } else {
      writer.println("ERROR");
      throw new Exception("Invalid server signature");
    }

    // We generate G^y

    BigInteger y = generatePrivateSymmetricKey(p);
    BigInteger gToTheY = g.modPow(y, p);

    writer.println(gToTheY);

    BigInteger symmetricPrivateValue = gToTheX.modPow(y, p);

    MessageDigest sha512 = MessageDigest.getInstance("SHA-512");

    byte[] digest = sha512.digest(symmetricPrivateValue.toByteArray());

    this.symmetricCipherKey = Arrays.copyOfRange(digest, 0, 32);
    this.symmetricHMACKey = Arrays.copyOfRange(digest, 32, 64);

    // We receive the IV
    this.iv = Base64.getDecoder().decode(reader.readLine());
  }

  private byte[] encryptWithSymmetricKey(byte[] data) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricCipherKey, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

    return cipher.doFinal(data);
  }

  private byte[] decryptWithSymmetricKey(byte[] data) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricCipherKey, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

    return cipher.doFinal(data);
  }

  private byte[] getHMAC(byte[] data) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA384");
    SecretKeySpec secretHMACKeySpec = new SecretKeySpec(symmetricHMACKey, "HmacSHA384");
    mac.init(secretHMACKeySpec);

    return mac.doFinal(data);
  }

  public void askServer(String id, String packageId) {
    System.out.println("Delegate client is connecting. Delegate: " + Thread.currentThread().getName());
    try (
        Socket socket = new Socket(Inet4Address.getLocalHost().getHostAddress(), 8000);
        OutputStream outputStream = socket.getOutputStream();
        PrintWriter writer = new PrintWriter(outputStream, true);
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()))
    ) {
      writer.println("SECINIT"); // We ask for initialization
      try {
        doChallenge(writer, reader);
        keyExchange(writer, reader);

        // ID message
        String idMessage = String.format("%s;%s",
            Base64.getEncoder().encodeToString(encryptWithSymmetricKey(id.getBytes())),
            Base64.getEncoder().encodeToString(getHMAC(id.getBytes()))
        );

        writer.println(idMessage);

        // Package message
        String packageMessage = String.format("%s;%s",
            Base64.getEncoder().encodeToString(encryptWithSymmetricKey(packageId.getBytes())),
            Base64.getEncoder().encodeToString(getHMAC(packageId.getBytes()))
        );

        writer.println(packageMessage);

        String result = reader.readLine();

        if (result.equals("ERROR")) {
          throw new Exception("Integrity violated");
        }

        String packageStatus = reader.readLine();

        List<byte[]> packageMessageAndHMAC = Arrays.stream(packageStatus.split(";")).map(Base64.getDecoder()::decode).toList();

        byte[] decryptedStatus = decryptWithSymmetricKey(packageMessageAndHMAC.getFirst());
        byte[] decryptedStatusHMAC = getHMAC(decryptedStatus);

        if (!Arrays.equals(decryptedStatusHMAC, packageMessageAndHMAC.getLast())) {
          writer.println("ERROR");
          throw new Exception("Integrity violated");
        }

        System.out.println(Thread.currentThread().getName() + ": El paquete consultado está en estado: " + new String(decryptedStatus));

        writer.println("TERMINAR");
        socket.close();
      } catch (Exception e) {
        e.printStackTrace(System.err);
        socket.close();
        System.out.println("Socket closed");
      }
    } catch (Exception e) {
      e.printStackTrace(System.err);
    }
  }
}
