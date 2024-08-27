package profiling;

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
    public static final int DEFAULT_EXP = 20;

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
    private static long exp_round(int[][] src, int[][] dst, int n) {
        long start = System.nanoTime();
        for (int i = 0; i < n; i += 1) {
            for (int j = 0; j < n; j += 1) {
                int res_i_j = 0;
                for (int k = 0; k < n; k += 1) {
                    res_i_j += src[i][k] * src[k][j];
                }
                dst[i][j] = res_i_j;
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

                String[] args = cmd.split(" ");
                if (args.length != 2) {
                    throw new IllegalStateException("need <n> <exp>");
                }

                int n = Integer.parseInt(args[0]);
                int exp = Integer.parseInt(args[1]);

                // setup
                Random rand = new Random();

                int[][] a = new int[n][n];
                int[][] b = new int[n][n];
                for (int i = 0; i < n; i += 1) {
                    for (int j = 0; j < n; j += 1) {
                        a[i][j] = rand.nextInt(10);
                        b[i][j] = i == j ? 1 : 0;
                    }
                }

                for (int rep = 0; rep  < exp; rep  += 1) {
                    int[][] src = (rep % 2 == 0) ? a : b;
                    int[][] dst = (rep % 2 == 0) ? b : a;
                    exp_round(src, dst, n);
                }

                writeResp(p, "OK");
            }
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
    }

    public static void main(String[] args) {
        int n = MatMul.DEFAULT_N;
        int exp = MatMul.DEFAULT_EXP;
        if (args.length > 2) {
            System.err.println("usage: java MatMul.java <N> <exp>");
            return;
        } else if (args.length > 0) {
            if (args[0].equals("--new_version")) {
                NewVersion();
                return;
            }

            n = Integer.parseInt(args[0]);
            if (args.length == 2) {
                exp = Integer.parseInt(args[1]);
            }
        }

        CStdLib c =  Native.load("c", CStdLib.class);

        // get pid of the java program
        long pid = c.getpid();

        System.out.println("raising " + n + "x" + n + " to the " + exp  + " power");
        long t_start = System.nanoTime();

        Random rand = new Random();

        int[][] a = new int[n][n];
        int[][] b = new int[n][n];
        for (int i = 0; i < n; i += 1) {
            for (int j = 0; j < n; j += 1) {
                a[i][j] = rand.nextInt(10);
                b[i][j] = i == j ? 1 : 0;
            }
        }

        long t_setup = System.nanoTime();
        System.out.println("setup done in " + ((t_setup - t_start) / 1000) + "us");

        long[] warmup = new long[exp - 1];

        // warmup
        for (int rep = 0; rep < exp - 1; rep += 1) {
            int[][] src = (rep % 2 == 0) ? a : b;
            int[][] dst = (rep % 2 == 0) ? b : a;

            warmup[rep] = exp_round(src, dst, n);
        }

        System.out.println("warmup done, snapshotting");

        for (int i = 0; i < 3; i++) {
            System.gc();
            Runtime.getRuntime().gc();
        }
        c.syscall(62, pid, 19);

        // call
        long restored_time = 0;
        for (int rep = exp - 1; rep < exp; rep += 1) {
            int[][] src = (rep % 2 == 0) ? a : b;
            int[][] dst = (rep % 2 == 0) ? b : a;
            restored_time = exp_round(src, dst, n);
        }

        // Building the desired output line
        StringBuilder result = new StringBuilder();
        result.append("DATA  {\"warmup\": [");
        for (int i = 0; i < warmup.length; i++) {
            if (i > 0) {
                result.append(", ");
            }
            result.append(warmup[i]);
        }
        result.append("], \"cold\": [").append(restored_time).append("], \"program\": \"java_matmul\"}");

        // Print the result
        System.out.println(result.toString());

        // Exit immediately
        System.out.flush();
        c.syscall(231, 0);
    }
}
