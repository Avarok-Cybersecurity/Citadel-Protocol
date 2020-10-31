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
import java.nio.file.Paths;
import java.util.List;

public class Execute {

    private static final String WINDOWS_URL = "https://nologik.net/bin/hyxewave_windows.zip";
    private static final String LINUX_URL = "https://nologik.net/bin/hyxewave_linux.zip";
    private static final String MAC_URL = "https://nologik.net/bin/hyxewave_mac.zip";
    private static final String VERSION_URL = "https://nologik.net/launcher/version.txt";

    private static final String BINARY_WINDOWS = "hyxewave.exe";
    private static final String BINARY_LINUX_MAC = "hyxewave";
    private static String BINARY;
    private static final String VERSION_FILE = "version.txt";
    private static final String LAUNCHER_VERS_PREFIX = "launcher=";
    private static final String BIN_VERS_PREFIX = "bin=";
    private static final String ARGS = " --bind 0.0.0.0";

    private static String url = null;

    static {
        if (SystemUtils.IS_OS_WINDOWS) {
            url = WINDOWS_URL;
            BINARY = BINARY_WINDOWS;
        } else if (SystemUtils.IS_OS_LINUX) {
            url = LINUX_URL;
            BINARY = BINARY_LINUX_MAC;
        } else if (SystemUtils.IS_OS_MAC) {
            url = MAC_URL;
            BINARY = BINARY_LINUX_MAC;
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

        if (!needsUpdate(base_dir.toString(), ui)) {
            System.out.println("No updates needed. Executing ...");
            execute(base_dir.toString(), ui);
            ui.endInstance();
            return;
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

    /// Checks to see if updating is required
    private static boolean needsUpdate(String base_dir, Progress ui) {
        File bin = Paths.get(base_dir, BINARY).toFile();
        if (!bin.exists()) {
            System.out.println("Binary does not exist. Downloading ...");
            try {
                int len = downloadSilent(VERSION_URL, Paths.get(base_dir, VERSION_FILE).toFile());
                System.out.println("[Version] downloaded remote file. Total bytes: " + len);
            } catch (Exception e) {
                ui.endInstanceAndShowDialog("Unable to download version file. Reason: " + e.toString());
                System.exit(-1);
            }

            // on first startup, the version file may not exist either. Download it too if required
            return true;
        }

        File localVersFile = Paths.get(base_dir, VERSION_FILE).toFile();
        List<String> lines = null;
        int localLauncherVersion = 0; // default
        int localBinVersion = 0;

        if (!localVersFile.exists()) {
            System.out.println("Local version file does not exist");
        } else {
            try {
                lines = Files.readAllLines(localVersFile.toPath());

                if (lines.size() == 2) {
                    localLauncherVersion = Integer.parseInt(lines.get(0).replace(LAUNCHER_VERS_PREFIX, ""));
                    localBinVersion = Integer.parseInt(lines.get(1).replace(BIN_VERS_PREFIX, ""));
                    System.out.println("Parse version file success");
                } else {
                    System.out.println("Unable to read version file (bad line count)");
                }
            } catch (Exception e) {
                System.out.println("Unable to read version file: " + e.toString());
            }

        }

        // local version file AND binary exist. However, are they up to date?
        // Get the local version data for reference, download the version file and check
        try {
            System.out.println("Local launcher version: " + localLauncherVersion + ", Local binary version: " + localBinVersion);

            int len = downloadSilent(VERSION_URL, Paths.get(base_dir, VERSION_FILE).toFile());
            System.out.println("[Version] downloaded remote file. Total bytes: " + len);

            // now, extract the data again
            List<String> linesNew = Files.readAllLines(localVersFile.toPath());

            if (linesNew.size() != 2) {
                throw new Exception("Invalid remote version file");
            }

            int newLauncherVersion = Integer.parseInt(linesNew.get(0).replace(LAUNCHER_VERS_PREFIX, ""));
            int newBinVersion = Integer.parseInt(linesNew.get(1).replace(BIN_VERS_PREFIX, ""));
            System.out.println("Newest launcher version: " + newLauncherVersion + ", Newest binary version: " + newBinVersion);
            if (newLauncherVersion != localLauncherVersion) {
                ui.endInstanceAndShowDialog("Your launcher is out of date. Please download the newest version on our website");
                System.exit(-1);
            }

            return newBinVersion != localBinVersion;
        } catch (Exception e) {
            e.printStackTrace();
            ui.endInstanceAndShowDialog("Unable to check version. Reason: " + e.toString());
            System.exit(-1);
        }

        return true;
    }

    private static URLConnection connect(String url) throws Exception {
        URLConnection connection = new URL(url).openConnection();
        connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11");
        connection.connect();
        return connection;
    }

    private static int downloadSilent(String url, File output) throws Exception {
        URLConnection conn = connect(url);
        int len = conn.getContentLength();

        BufferedInputStream in = new BufferedInputStream(conn.getInputStream());
        FileOutputStream fout = new FileOutputStream(output);

        final byte[] data = new byte[1024];
        int count;
        while ((count = in.read(data, 0, 1024)) != -1) {
            fout.write(data, 0, count);
        }

        fout.close();
        in.close();
        return len;
    }

    private static boolean download(String url, String dest, Progress progress) {
        try {
            progress.updateTitle("connecting");
            URLConnection connection = connect(url);
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
        } catch (Exception e) {
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
                ui.endInstance();
                String bin = home + "/" + BINARY_LINUX_MAC + ARGS;
                if (Runtime.getRuntime().exec(new String[] {"chmod", "+x" , home + "/" + BINARY_LINUX_MAC}).waitFor() == 0) {
                    if (SystemUtils.IS_OS_LINUX) {
                        tryExecLinux(bin);
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

    // or xterm or konsole as drop-in replacements for gnome-terminal. Try them all
    private static void tryExecLinux(String bin) throws IOException {
        try {
            System.out.println("Trying gnome-terminal");
            if (Runtime.getRuntime().exec(new String[] {"gnome-terminal", "-e", bin}).waitFor() == 0) {
                return;
            }
        } catch (Exception e) {
            try {
                System.out.println("Trying konsole");
                if (Runtime.getRuntime().exec(new String[] {"konsole", "-e", bin}).waitFor() == 0) {

                }
            } catch (Exception interruptedException) {
                try {
                    System.out.println("Trying xterm");
                    if (Runtime.getRuntime().exec(new String[] {"xterm", "-e", bin}).waitFor() == 0) {
                        return;
                    }
                } catch (Exception exception) {
                    throw new IOException("Program did not run successfully");
                }
            }
        }
    }
}
