package profiling;

import org.json.simple.JSONValue;
import org.json.simple.JSONObject;

import java.util.Random;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;

import com.sun.jna.Library;
import com.sun.jna.Native;

class MatMul {
    public static final int DEFAULT_N = 100;
    public static final int WARMUP = 10;

    public interface CStdLib extends Library {
        int syscall(int number, Object... args);
        int getpid ();
    }


    public static void snapshotPrepare() {
        for (int i = 0; i < 3; i++) {
            System.gc();
            Runtime.getRuntime().gc();
        }
    }

    private static void writeResp(PrintWriter p, String message) {
        p.write(message);
        p.flush();
    }

    private static void exp(int n, int exp) {
    }

    // return time
    private static long mul(int[][] a, int[][] b, int[][] result, int n) {
        long start = System.nanoTime();
        for (int i = 0; i < n; i += 1) {
            for (int j = 0; j < n; j += 1) {
                int res_i_j = 0;
                for (int k = 0; k < n; k += 1) {
                    res_i_j += a[i][k] * b[k][j];
                }
                result[i][j] = res_i_j;
            }
        }
        return System.nanoTime() - start;
    }

    public static void NewVersion() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/serverless/chan0"));) {
            PrintWriter p = new PrintWriter(new FileOutputStream("/serverless/chan0"));
            String cmd;
            while ((cmd = reader.readLine()) != null) {
                cmd = cmd.trim();
                if (cmd.equals("SNAPSHOT_PREPARE")) {
                    snapshotPrepare();
                    writeResp(p, "OK");
                    continue;
                }

                JSONObject args = (JSONObject) JSONValue.parse(cmd);

                int n = Math.toIntExact((long) args.get("N"));

                // setup
                Random rand = new Random();

                int[][] a = new int[n][n];
                int[][] b = new int[n][n];
                int[][] res = new int[n][n];
                for (int i = 0; i < n; i += 1) {
                    for (int j = 0; j < n; j += 1) {
                        a[i][j] = rand.nextInt(10);
                        b[i][j] = rand.nextInt(10);
                    }
                }

                mul(a, b, res, n);

                writeResp(p, "OK");
            }
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
    }

    public static void main(String[] args) {
        int n = MatMul.DEFAULT_N;
        if (args.length > 2) {
            System.err.println("usage: java MatMul.java <N>");
            return;
        } else if (args.length > 0) {
            if (args[0].equals("--new_version")) {
                NewVersion();
                return;
            }

            n = Integer.parseInt(args[0]);
        }

        CStdLib c =  Native.load("c", CStdLib.class);

        // get pid of the java program
        long pid = c.getpid();

        System.out.println("multiplying 2 " + n + "x" + n + " matrices");
        long t_start = System.nanoTime();

        Random rand = new Random();

        int[][] a = new int[n][n];
        int[][] b = new int[n][n];
        int[][] result = new int[n][n];
        for (int i = 0; i < n; i += 1) {
            for (int j = 0; j < n; j += 1) {
                a[i][j] = rand.nextInt(10);
                b[i][j] = rand.nextInt(10);
            }
        }

        long t_setup = System.nanoTime();
        System.out.println("setup done in " + ((t_setup - t_start) / 1000) + "us");

        long[] warmup = new long[WARMUP];

        // warmup
        for (int rep = 0; rep < WARMUP; rep += 1) {
            warmup[rep] = mul(a, b, result, n);
        }

        System.out.println("warmup done, snapshotting");

        for (int i = 0; i < 3; i++) {
            System.gc();
            Runtime.getRuntime().gc();
        }
        c.syscall(62, pid, 19);

        // call
        long restored_time = restored_time = mul(a, b, result, n);

        // Building the desired output line
        StringBuilder output = new StringBuilder();
        output.append("DATA  {\"warmup\": [");
        for (int i = 0; i < warmup.length; i++) {
            if (i > 0) {
                output.append(", ");
            }
            output.append(warmup[i]);
        }
        output.append("], \"cold\": [").append(restored_time).append("], \"program\": \"java_matmul\"}");

        // Print the result
        System.out.println(output.toString());

        // Exit immediately
        System.out.flush();
        c.syscall(231, 0);
    }
}
