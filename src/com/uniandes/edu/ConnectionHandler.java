package com.uniandes.edu;

import javax.crypto.*;
import javax.crypto.interfaces.DHKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ConnectionHandler extends Thread {
  private final Socket socket;
  private final PrivateKey privateKey;

  private byte[] symmetricCipherKey;
  private byte[] symmetricHMACKey;
  private final byte[] iv = new byte[16];

  public ConnectionHandler(Socket socket, PrivateKey privateKey) {
    this.socket = socket;
    this.privateKey = privateKey;
  }

  private String decryptWithPrivateKey(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    byte[] originalData = Base64.getDecoder().decode(data);
    return new String(cipher.doFinal(originalData));
  }

  private BigInteger generatePrivateSymmetricKey(BigInteger p) {
    SecureRandom random = new SecureRandom();
    return new BigInteger(1024, random).mod(p.subtract(BigInteger.ONE));
  }

  private byte[] signArrays(byte[]... arrays) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
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
    signature.initSign(privateKey);
    signature.update(concatenated);
    return signature.sign();
  }

  public void keyExchange(BufferedReader input, PrintWriter output) throws Exception {
    String r = input.readLine();

    String decrypted = decryptWithPrivateKey(r);

    output.println(decrypted);

    String result = input.readLine();

    if (result.equals("ERROR")) throw new Exception("Failed to exchange the key");

    Process process = Runtime.getRuntime().exec("openssl dhparam -text 1024");

    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    StringBuilder processOutput = new StringBuilder();
    String line;

    while ((line = reader.readLine()) != null) {
      processOutput.append(line).append("\n");
    }

    Pattern pPattern = Pattern.compile("P:\\s*([0-9a-fA-F:]+)");
    Matcher pMatcher = pPattern.matcher(processOutput.toString());

    Pattern gPattern = Pattern.compile("G:\\s*(\\d+)");
    Matcher gMatcher = gPattern.matcher(processOutput.toString());

    BigInteger p = null;
    BigInteger g = null;

    if (pMatcher.find()) {
      String pHex = pMatcher.group(1).replaceAll(":", "");
      p = new BigInteger(pHex, 16);
    }

    if (gMatcher.find()) {
      g = new BigInteger(gMatcher.group(1));
    }

    if (p == null || g == null) {
      throw new Exception("Failed to generate P and G");
    }

    BigInteger x = generatePrivateSymmetricKey(p);
    BigInteger gToTheX = g.modPow(x, p);

    output.println(g);
    output.println(p);
    output.println(gToTheX);

    byte[] signedParams = signArrays(g.toByteArray(), p.toByteArray(), gToTheX.toByteArray());

    output.println(Base64.getEncoder().encodeToString(signedParams));

    if (input.readLine().equals("ERROR")) throw new Exception("Failed to exchange the key");

    BigInteger gToTheY = new BigInteger(input.readLine());

    BigInteger privateSymmetricValue = gToTheY.modPow(x, p);
    MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
    byte[] digest = sha512.digest(privateSymmetricValue.toByteArray());

    this.symmetricCipherKey = Arrays.copyOfRange(digest, 0, 32);
    this.symmetricHMACKey = Arrays.copyOfRange(digest, 32, 64);

    // Now we send the IV.

    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(iv);

    output.println(Base64.getEncoder().encodeToString(iv));
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

  @Override
  public void run() {
    try (
      BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
      PrintWriter output =  new PrintWriter(socket.getOutputStream(), true)
    ) {
      boolean waitForInit = true;
      String chunk;
      while (waitForInit && (chunk = input.readLine()) != null) {
        if (chunk.equals("SECINIT")) {
          waitForInit = false;
        }
      }

      keyExchange(input, output);

      String idMessage = input.readLine();
      String packageMessage = input.readLine();

      List<byte[]> idMessageAndHMAC = Arrays.stream(idMessage.split(";")).map(Base64.getDecoder()::decode).toList();

      byte[] decryptedId = decryptWithSymmetricKey(idMessageAndHMAC.getFirst());
      byte[] decryptedIdHMAC = getHMAC(decryptedId);

      if (!Arrays.equals(decryptedIdHMAC, idMessageAndHMAC.getLast())) {
        // Integrity failed
        output.println("ERROR");
        throw new Exception("Integrity violated");
      }

      List<byte[]> packageMessageAndHMAC = Arrays.stream(packageMessage.split(";")).map(Base64.getDecoder()::decode).toList();

      byte[] decryptedPackage = decryptWithSymmetricKey(packageMessageAndHMAC.getFirst());
      byte[] decryptedPackageHMAC = getHMAC(decryptedPackage);

      if (!Arrays.equals(decryptedPackageHMAC, packageMessageAndHMAC.getLast())) {
        // Integrity failed
        output.println("ERROR");
        throw new Exception("Integrity violated");
      }
      output.println("OK");

      String userId = new String(decryptedId);
      String packageId = new String(decryptedPackage);

      Package p = Server.findPackage(userId, packageId);

      String response = p == null ? Status.DESCONOCIDO.toString() : p.getStatus().toString();

      byte[] encryptedResponse = encryptWithSymmetricKey(response.getBytes());
      byte[] responseHMAC = getHMAC(response.getBytes());

      output.println(String.format("%s;%s", Base64.getEncoder().encodeToString(encryptedResponse), Base64.getEncoder().encodeToString(responseHMAC)));

      String result = input.readLine();

      if (result.equals("ERROR")) {
        throw new Exception("Integrity violated");
      } else if (!result.equals("TERMINAR")) {
        throw new Exception("Protocol violated");
      }
    } catch (Exception e) {
      e.printStackTrace(System.err);
    } finally {
      try {
        socket.close();
        System.out.println("Socket closed");
      } catch (IOException e) {
        e.printStackTrace(System.err);
      }
    }
  }
}
