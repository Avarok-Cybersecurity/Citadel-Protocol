package com.satori;

import com.satori.swing.Progress;
import net.lingala.zip4j.ZipFile;
import org.apache.commons.lang3.SystemUtils;

import javax.swing.*;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;

public class Execute {

    private static final String WINDOWS_URL = "https://nologik.net/bin/hyxewave_windows.zip";
    private static final String LINUX_URL = "https://nologik.net/bin/hyxewave_linux.zip";
    private static final String MAC_URL = "https://nologik.net/bin/hyxewave_mac.zip";
    private static final String BINARY_WINDOWS = "hyxewave.exe";
    private static final String BINARY_LINUX_MAC = "hyxewave";
    private static final String ARGS = " --bind 0.0.0.0";

    private static String url = null;

    static {
        if (SystemUtils.IS_OS_WINDOWS) {
            url = WINDOWS_URL;
        } else if (SystemUtils.IS_OS_LINUX) {
            url = LINUX_URL;
        } else if (SystemUtils.IS_OS_MAC) {
            url = MAC_URL;
        } else {
            JOptionPane.showMessageDialog(null, "Incompatible operating system");
            System.exit(-1);
        }
    }

    public static void main(String... args) {
        Progress.startInstance();
    }

    public static void startUpdater(Progress ui) {
        String user_home = System.getProperty("user.home");
        Path base_dir = FileSystems.getDefault().getPath(user_home, ".HyxeWave");
        if (Files.notExists(base_dir)) {
            try {
                Files.createDirectory(base_dir);
                System.out.println("First-run init success");
            } catch (IOException e) {
                ui.endInstanceAndShowDialog("Unable to create base directory. Check permissions");
                return;
            }
        }

        String dest = base_dir.toString() + "/tmp.zip";
        // now, download the file
        if (download(url, dest, ui)) {
            // now, unzip
            if (unzip(dest, base_dir.toString())) {
                // now, execute the file
                execute(base_dir.toString(), ui);
                ui.endInstance();
            } else {
                ui.endInstanceAndShowDialog("Unable to extract image. Please check permissions");
            }
        } else {
            ui.endInstanceAndShowDialog("Unable to download image. Please try again later");
        }
    }

    private static boolean download(String url, String dest, Progress progress) {
        try {
            progress.updateTitle("connecting");
            URLConnection connection = new URL(url).openConnection();
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11");
            connection.connect();
            int len = connection.getContentLength();
            progress.setProgressIndeterminate(false);
            progress.setProgressLength(len);
            progress.updateTitle("downloading");

            BufferedInputStream in = new BufferedInputStream(connection.getInputStream());
            FileOutputStream fout = new FileOutputStream(dest);

            final byte[] data = new byte[1024];
            int count;
            int downloaded = 0;
            while ((count = in.read(data, 0, 1024)) != -1) {
                fout.write(data, 0, count);
                downloaded += count;
                progress.tickProgressBar(downloaded);
            }

            System.out.println("Downloaded " + len + " bytes");
            fout.close();
            in.close();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    private static boolean unzip(String file, String dest) {
        try {
            new ZipFile(new File(file))
                    .extractAll(dest);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    /// Linux/mac will need to chmod
    private static void execute(String home, Progress ui) {
        try {
            if (SystemUtils.IS_OS_WINDOWS) {
                String bin = home + "\\" + BINARY_WINDOWS + ARGS;
                System.out.println(bin);
                if (Runtime.getRuntime().exec(new String[] {"cmd", "/c", "start", "cmd.exe", "/c", bin}).waitFor() != 0) {
                    throw new IOException("Program did not run successfully");
                }
            } else if (SystemUtils.IS_OS_LINUX || SystemUtils.IS_OS_MAC) {
                String bin = home + "/" + BINARY_LINUX_MAC + ARGS;
                if (Runtime.getRuntime().exec(new String[] {"chmod", "+x" , bin}).waitFor() == 0) {
                    if (SystemUtils.IS_OS_LINUX) {
                        // or xterm or konsole as drop-in replacements for gnome-terminal. Try them all
                        if (Runtime.getRuntime().exec(new String[] {"gnome-terminal", "-e", bin}).waitFor() != 0) {
                            if (Runtime.getRuntime().exec(new String[] {"konsole", "-e", bin}).waitFor() != 0) {
                                if (Runtime.getRuntime().exec(new String[] {"xterm", "-e", bin}).waitFor() != 0) {
                                    throw new IOException("Program did not run successfully");
                                }
                            }
                        }
                    } else {
                        // osascript -e 'tell app "Terminal" to do script "echo hello"'
                        String macCmd = "'tell app \"Terminal\" to do script \"" + bin + "\"'";
                        if (Runtime.getRuntime().exec(new String[] {"osascript", "-e", macCmd}).waitFor() != 0) {
                            throw new IOException("Program did not run successfully");
                        }
                    }
                } else {
                    throw new IOException("Unable to chmod");
                }
            } else {
                throw new IOException("Operating system not supported");
            }
        } catch (IOException | InterruptedException e) {
            ui.endInstanceAndShowDialog("Unable to execute binary. Reason: " + e.toString());
        }
    }
}
