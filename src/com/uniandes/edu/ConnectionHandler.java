package com.uniandes.edu;

import com.uniandes.edu.times.Time;
import com.uniandes.edu.times.TimeCollector;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ConnectionHandler implements Runnable {
  private final Socket socket;
  private final PrivateKey privateKey;
  private final byte[] iv = new byte[16];
  private byte[] symmetricCipherKey;
  private byte[] symmetricHMACKey;

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

    Time challengeTime = new Time("32-Clients");

    String decrypted = decryptWithPrivateKey(r);

    output.println(decrypted);

    challengeTime.close();

    //TimeCollector.saveConcurrentChallenge(challengeTime, 32);

    String result = input.readLine();

    if (result.equals("ERROR")) throw new Exception("Failed to exchange the key");

    Time paramsGeneration = new Time("32-Clients");

    ProcessBuilder processBuilder = new ProcessBuilder();
    processBuilder.command("openssl", "dhparam", "-text", "1024");
    Process process = processBuilder.start();

    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    StringBuilder processOutput = new StringBuilder();
    String line;

    while ((line = reader.readLine()) != null) {
      processOutput.append(line).append("\n");
    }

    process.waitFor();

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

    paramsGeneration.close();
    //TimeCollector.saveConcurrentParamsGeneration(paramsGeneration, 32);

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
    System.out.println("Server accepted a client. Delegate: " + Thread.currentThread().getName() + "\n" +
        "Socket: " + socket.toString());
    try (
        BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter output = new PrintWriter(socket.getOutputStream(), true)
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

      Time verifyRequest = new Time("32-Clients");

      List<byte[]> idMessageAndHMAC = Arrays.stream(idMessage.split(";")).map(Base64.getDecoder()::decode).toList();

      byte[] decryptedId = decryptWithSymmetricKey(idMessageAndHMAC.getFirst());
      byte[] decryptedIdHMAC = getHMAC(decryptedId);

      boolean verified = Arrays.equals(decryptedIdHMAC, idMessageAndHMAC.getLast());

      verifyRequest.close();
      //TimeCollector.saveConcurrentVerifyRequest(verifyRequest, 32);

      if (!verified) {
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

      Time symmetricTime = new Time();
      byte[] encryptedResponse = encryptWithSymmetricKey(response.getBytes());
      symmetricTime.close();
      TimeCollector.saveSymmetric(symmetricTime);

      Time asymmetricTime = new Time();

      Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.ENCRYPT_MODE, privateKey);
      cipher.doFinal(response.getBytes());

      asymmetricTime.close();
      TimeCollector.saveAsymmetric(asymmetricTime);

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
      } catch (IOException e) {
        e.printStackTrace(System.err);
      }
    }
    System.out.println("Socket closed. Delegate: " + Thread.currentThread().getName());
  }
}
