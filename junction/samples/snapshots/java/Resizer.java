package profiling;

import javax.imageio.ImageIO;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import com.sun.jna.Library;
import com.sun.jna.Native;


class Resizer {
    Image resizeImage(Image bufferedImage, int width, int height) {
        return bufferedImage.getScaledInstance(width, height, Image.SCALE_DEFAULT);
    }

    public interface CStdLib extends Library {
        int syscall(int number, Object... args);
        int getpid ();
    }


    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("usage: java Resizer.java <img path>");
            return;
        }

        CStdLib c =  Native.load("c", CStdLib.class);

        BufferedImage bi;
        Process p;
        try {
            // get pid of the java program
            long pid = c.getpid();

            bi = ImageIO.read(new File(args[0]));
            Resizer resizer = new Resizer();

            // warmup function
            for (int i = 0; i < 5; i++) {
                resizer.resizeImage(bi, 30, 30);
            }

            System.gc();
            // stop the process for inspection
            c.syscall(62, pid, 19);

            // run the function again to profile
            resizer.resizeImage(bi, 30, 30);

            System.out.println("Done resizing!");

        } catch (IOException e) {
            System.err.println("No image file found");
            e.printStackTrace();
        }
    }
}
