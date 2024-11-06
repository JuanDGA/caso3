package com.uniandes.edu.times;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class TimeCollector {
  private final static PrintWriter iterativeChallengePrinter;
  private final static PrintWriter concurrentChallengePrinter4Delegates;
  private final static PrintWriter concurrentChallengePrinter8Delegates;
  private final static PrintWriter concurrentChallengePrinter32Delegates;

  private final static PrintWriter iterativeParamsGenerationPrinter;
  private final static PrintWriter concurrentParamsGenerationPrinter4Delegates;
  private final static PrintWriter concurrentParamsGenerationPrinter8Delegates;
  private final static PrintWriter concurrentParamsGenerationPrinter32Delegates;

  private final static PrintWriter iterativeVerifyRequestPrinter;
  private final static PrintWriter concurrentVerifyRequestPrinter4Delegates;
  private final static PrintWriter concurrentVerifyRequestPrinter8Delegates;
  private final static PrintWriter concurrentVerifyRequestPrinter32Delegates;

  static {
    try {
      iterativeChallengePrinter = new PrintWriter(
          new FileWriter("data/times/iterativeChallenge", true), true);
      concurrentChallengePrinter4Delegates = new PrintWriter(
          new FileWriter("data/times/fourDelegatesChallenge", true), true);
      concurrentChallengePrinter8Delegates = new PrintWriter(
          new FileWriter("data/times/eightDelegatesChallenge", true), true);
      concurrentChallengePrinter32Delegates = new PrintWriter(
          new FileWriter("data/times/thirtyTwoDelegatesChallenge", true), true);

      iterativeParamsGenerationPrinter = new PrintWriter(
          new FileWriter("data/times/iterativeParamsGeneration", true), true);
      concurrentParamsGenerationPrinter4Delegates = new PrintWriter(
          new FileWriter("data/times/fourDelegatesParamsGeneration", true), true);
      concurrentParamsGenerationPrinter8Delegates = new PrintWriter(
          new FileWriter("data/times/eightDelegatesParamsGeneration", true), true);
      concurrentParamsGenerationPrinter32Delegates = new PrintWriter(
          new FileWriter("data/times/thirtyTwoDelegatesParamsGeneration", true), true);

      iterativeVerifyRequestPrinter = new PrintWriter(
          new FileWriter("data/times/iterativeVerifyRequest", true), true);
      concurrentVerifyRequestPrinter4Delegates = new PrintWriter(
          new FileWriter("data/times/fourDelegatesVerifyRequest", true), true);
      concurrentVerifyRequestPrinter8Delegates = new PrintWriter(
          new FileWriter("data/times/eightDelegatesVerifyRequest", true), true);
      concurrentVerifyRequestPrinter32Delegates = new PrintWriter(
          new FileWriter("data/times/thirtyTwoDelegatesVerifyRequest", true), true);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static synchronized void saveIterativeChallenge(Time time) {
    iterativeChallengePrinter.println(time);
  }

  public static synchronized void saveConcurrentChallenge(Time time, int delegates) {
    switch (delegates) {
      case 4:
        concurrentChallengePrinter4Delegates.println(time);
        break;
      case 8:
        concurrentChallengePrinter8Delegates.println(time);
        break;
      case 32:
        concurrentChallengePrinter32Delegates.println(time);
        break;
    }
  }

  public static synchronized void saveIterativeParamsGeneration(Time time) {
    iterativeParamsGenerationPrinter.println(time);
  }

  public static synchronized void saveConcurrentParamsGeneration(Time time, int delegates) {
    switch (delegates) {
      case 4:
        concurrentParamsGenerationPrinter4Delegates.println(time);
        break;
      case 8:
        concurrentParamsGenerationPrinter8Delegates.println(time);
        break;
      case 32:
        concurrentParamsGenerationPrinter32Delegates.println(time);
        break;
    }
  }

  public static synchronized void saveIterativeVerifyRequest(Time time) {
    iterativeVerifyRequestPrinter.println(time);
  }

  public static synchronized void saveConcurrentVerifyRequest(Time time, int delegates) {
    switch (delegates) {
      case 4:
        concurrentVerifyRequestPrinter4Delegates.println(time);
        break;
      case 8:
        concurrentVerifyRequestPrinter8Delegates.println(time);
        break;
      case 32:
        concurrentVerifyRequestPrinter32Delegates.println(time);
        break;
    }
  }
}
