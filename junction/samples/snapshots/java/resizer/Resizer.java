package profiling;

import javax.imageio.ImageIO;

import java.awt.*;
import java.awt.image.BufferedImage;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;

import com.sun.jna.Library;
import com.sun.jna.Native;


class Resizer {
    public static Image resizeImage(Image bufferedImage, int width, int height) {
        return bufferedImage.getScaledInstance(width, height, Image.SCALE_DEFAULT);
    }

    public static int getImageWidth(Image image) {
        if (image instanceof BufferedImage) {
            return ((BufferedImage) image).getWidth();
        } else {
            return image.getWidth(null);
        }
    }

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

                BufferedImage bi = ImageIO.read(new File(cmd));
                BufferedImage bufferedImageResult = new BufferedImage(
                        30,
                        30,
                        bi.getType()
                );
                Graphics2D g2d = bufferedImageResult.createGraphics();
                g2d.drawImage(
                        bi,
                        0,
                        0,
                        30,
                        30,
                        null
                );
                g2d.dispose();
                Boolean ret = ImageIO.write(bufferedImageResult, "png", new FileOutputStream("/tmp/image.png"));
                if (!ret) {
                    throw new IllegalStateException("failed to write image");
                }
                writeResp(p, "OK");
            }
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
    }

    public static void main(String[] args) {

        if (args.length > 0 && args[0].equals("--new_version")) {
            NewVersion();
            return;
        }

        if (args.length < 1) {
            System.err.println("usage: java Resizer.java <img path>");
            return;
        }

        CStdLib c =  Native.load("c", CStdLib.class);

        String prog_name = "java_resizer";
        if (args.length > 1) {
            prog_name = args[1];
        }


        long[] warmups = new long[5];
        int[] sizes = new int[5];

        Boolean dont_stop = System.getenv("DONTSTOP") != null;

        BufferedImage bi;
        Process p;
        Image x;
        try {
            // get pid of the java program
            long pid = c.getpid();

            bi = ImageIO.read(new File(args[0]));
            Resizer resizer = new Resizer();

            // warmup function
            for (int i = 0; i < 5; i++) {
                long startTime = System.nanoTime();
                x = resizer.resizeImage(bi, 30, 30);
                long endTime = System.nanoTime();
                warmups[i] = endTime - startTime;
                sizes[i] = getImageWidth(x);
            }

            for (int i = 0; i < 3; i++) {
                System.gc();
                Runtime.getRuntime().gc();
            }
            // stop the process for inspection
            if (!dont_stop) {
                c.syscall(62, pid, 19);
            }

            long startTime = System.nanoTime();

            // run the function again to profile
            x = resizer.resizeImage(bi, 30, 30);

            long endTime = System.nanoTime();

            System.out.println("Done resizing!");

            // Building the desired output line
            StringBuilder result = new StringBuilder();
            result.append("DATA  {\"warmup\": [");
            for (int i = 0; i < warmups.length; i++) {
                if (i > 0) {
                    result.append(", ");
                }
                result.append(warmups[i]);
            }
            result.append("], \"cold\": [").append(endTime - startTime).append("], \"program\": \"" + prog_name + "\"}");

            // Print the result
            System.out.println(result.toString());

            // Exit immediately
            System.out.flush();
            c.syscall(231, 0);

            System.out.println(x);
            System.out.println(sizes);

        } catch (IOException e) {
            System.err.println("No image file found");
            e.printStackTrace();
        }
    }
}
