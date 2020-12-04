package com.satori;

import com.satori.swing.Progress;
import net.lingala.zip4j.ZipFile;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.SystemUtils;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class Execute {

    private static final String WINDOWS_URL = "https://nologik.net/bin/hyxewave_windows.zip";
    private static final String LINUX_URL = "https://nologik.net/bin/hyxewave_linux.zip";
    private static final String MAC_URL = "https://nologik.net/bin/hyxewave_mac.zip";
    private static final String VERSION_URL = "https://nologik.net/launcher/version.txt";
    private static final String LAUNCHER_URL = "https://nologik.net/launcher/launcher.jar";

    private static final String BINARY_WINDOWS = "hyxewave.exe";
    private static final String BINARY_LINUX_MAC = "hyxewave";
    private static String BINARY;
    private static final String VERSION_FILE = "version.txt";
    private static final String LAUNCHER_VERS_PREFIX = "launcher=";
    private static final String BIN_VERS_PREFIX = "bin=";
    private static final String ARGS = " --launcher";

    private static final String ARCHIVE_SAVE = "/tmp.zip";
    private static final String LOCK_FILE = "fs.lock";

    private static final int VERSION = 4;

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
        Displayable.startInstance(args);
    }

    public static void startUpdater(Displayable ui, String... args) {
        String user_home = System.getProperty("user.home");
        Path base_dir = FileSystems.getDefault().getPath(user_home, ".HyxeWave");

        if (Files.notExists(base_dir)) {
            try {
                Files.createDirectory(base_dir);
                System.out.println("First-run init success");
            } catch (IOException e) {
                ui.endInstanceAndShowMessage("Unable to create base directory. Check permissions");
                return;
            }
        }

        File lock = base_dir.resolve(LOCK_FILE).toFile();

        try {
            if (!lock.createNewFile()) {
                ui.endInstanceAndShowMessage("Launcher already running");
                System.exit(-1);
            }

            lock.deleteOnExit();
        } catch (Exception e) {
            ui.endInstanceAndShowMessage("Unable to create lockfile @ " + lock.toString() + ". Reason: " + e.toString());
            System.exit(-1);
        }


        if (needsUpdate(base_dir.toString(), ui)) {
            String dest = base_dir.toString() + ARCHIVE_SAVE;
            // now, download the file
            if (download(url, dest, ui)) {
                // now, unzip
                if (unzip(dest, base_dir.toString())) {
                    // now, execute the file
                    execute(user_home, base_dir.toString(), ui, args);
                    ui.endInstance();
                } else {
                    ui.endInstanceAndShowMessage("Unable to extract image. Please check permissions");
                }
            } else {
                ui.endInstanceAndShowMessage("Unable to download image. Please try again later");
            }
        } else {
            System.out.println("No updates needed. Executing ...");
            execute(user_home, base_dir.toString(), ui, args);
            ui.endInstance();
        }
    }

    /// Checks to see if updating is required
    private static boolean needsUpdate(String base_dir, Displayable ui) {
        File bin = Paths.get(base_dir, BINARY).toFile();
        if (!bin.exists()) {
            System.out.println("Binary does not exist. Downloading ...");
            try {
                int len = downloadSilent(VERSION_URL, Paths.get(base_dir, VERSION_FILE).toFile());
                System.out.println("[Version] downloaded remote file. Total bytes: " + len);
            } catch (Exception e) {
                ui.endInstanceAndShowMessage("Unable to download version file. Reason: " + e.toString());
                System.exit(-1);
            }

            // on first startup, the version file may not exist either. Download it too if required
            return true;
        }

        File localVersFile = Paths.get(base_dir, VERSION_FILE).toFile();
        List<String> lines;
        int localLauncherVersion = VERSION; // default
        int localBinVersion = 0;

        if (!localVersFile.exists()) {
            System.out.println("Local version file does not exist");
        } else {
            try {
                lines = Files.readAllLines(localVersFile.toPath());

                if (lines.size() == 2) {
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
                ui.endInstanceAndShowMessage("Your launcher is out of date. Will now redirect you to the following link upon exit\n" + LAUNCHER_URL);
                openWebpage(new URL(LAUNCHER_URL));
                System.exit(-1);
            }

            return newBinVersion != localBinVersion;
        } catch (Exception e) {
            e.printStackTrace();
            ui.endInstanceAndShowMessage("Unable to check version. Reason: " + e.toString());
            System.exit(-1);
        }

        return true;
    }

    private static boolean openWebpage(URL url) {
        if (Desktop.isDesktopSupported()) {
            Desktop desktop = Desktop.getDesktop();
            if (desktop.isSupported(Desktop.Action.BROWSE)) {
                try {
                    desktop.browse(url.toURI());
                    return false;
                } catch (URISyntaxException | IOException ignored) {
                }
            }
        }

        return false;
    }

    /*
    /// Will attempt to update the launcher, but if not possible, will return false
    private static boolean updateLauncher() {
        try {
            CodeSource codeSource = Execute.class.getProtectionDomain().getCodeSource();
            File jarFile = new File(codeSource.getLocation().toURI().getPath());

            String jarDir = jarFile.getPath();
            if (jarDir.endsWith("jar")) {
                Runtime.getRuntime().exec("cmd /c ping localhost -n 1 > nul && del " + jarDir).waitFor();
                System.exit(0);
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }*/

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

    private static boolean download(String url, String dest, Displayable progress) {
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
            progress.endInstanceAndShowMessage("Error downloading: " + e.toString());
            return false;
        }
    }

    private static boolean unzip(String file, String dest) {
        try {
            File archive = new File(file);
            new ZipFile(archive)
                    .extractAll(dest);
            return archive.delete();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    /// Linux/mac will need to chmod
    private static void execute(String user_home, String home, Displayable ui, String... args) {
        try {
            if (SystemUtils.IS_OS_WINDOWS) {
                String bin = home + "\\" + BINARY_WINDOWS + ARGS;
                System.out.println(bin);
                if (Runtime.getRuntime().exec(flattenCommand(new String[] {"cmd", "/c", "start", "cmd.exe", "/c", bin}, args)).waitFor() != 0) {
                    throw new IOException("Program did not run successfully");
                }
            } else if (SystemUtils.IS_OS_LINUX || SystemUtils.IS_OS_MAC) {
                ui.endInstance();
                String binPath = home + "/" + BINARY_LINUX_MAC;
                String bin = binPath + ARGS;

                if (Runtime.getRuntime().exec(new String[] {"chmod", "+x" , home + "/" + BINARY_LINUX_MAC}).waitFor() == 0) {
                    if (SystemUtils.IS_OS_LINUX) {
                        tryExecLinux(home, bin, !ui.isGUI(), args);
                    } else {
                        // first, we need to strip the unidentified metadata from the binary with:
                        // xattr -dr com.apple.quarantine "unidentified_thirdparty.app"
                        Runtime.getRuntime().exec(new String[] {"xattr", "-dr", "com.apple.quarantine", "\"" + binPath + "\""}).waitFor();
                        // osascript -e 'tell app "Terminal" to do script "CMD"'
                        // we need to embed the args inside the command here
                        //String macCmd = "'tell app \"Terminal\" to do script \"" + bin + " " + String.join(" ", args != null? args : new String[]{}) + "\" with administrator privileges'";
                        execMac(home, binPath, args);
                    }
                } else {
                    throw new IOException("Unable to chmod");
                }
            } else {
                throw new IOException("Operating system not supported");
            }
        } catch (Exception e) {
            ui.endInstanceAndShowMessage("Unable to execute binary. Reason: " + e.toString());
        }
    }

    private static String[] flattenCommand(String[] base, String... args) {
        return ArrayUtils.addAll(base, args);
    }

    // or xterm or konsole as drop-in replacements for gnome-terminal. Try them all
    private static void tryExecLinux(String home, String bin, boolean noGUI, String... args) throws Exception {
        // "shopt -u huponexit; java -jar myjar.jar"
        System.out.println("Trying to exec ...");
        // String terminalCmd = getConsoleCommand().map(cmd -> cmd + " -e pkexec " + bin).orElse("sudo " + bin) + (args.length != 0 ? " " + String.join(" ", args) : "");
        String terminalCmd = getConsoleCommand().map(cmd -> cmd + " -e " + bin).orElse(bin) + (args.length != 0 ? " " + String.join(" ", args) : "");
        System.out.println("sh: " + terminalCmd);
        Path file = noGUI ? writeLinesToFile(home, "start.sh", terminalCmd) : writeLinesToFile(home,"start.sh", "shopt -u huponexit", terminalCmd);
        chmod(file);

        if (noGUI) {
            new ProcessBuilder("sh", file.toString()).inheritIO().start().waitFor();
        } else {
            Runtime.getRuntime().exec(new String[] {"sh", file.toString()}).waitFor();
        }
    }

    private static Optional<String> getConsoleCommand() {
        final String[][] cmds = new String[][] {new String[] {"gnome-terminal", "--help"}, new String[] {"konsole", "--help"}, new String[] {"xterm", "--help"}};

        for (String[] cmd : cmds) {
            try {
                Runtime.getRuntime().exec(cmd).waitFor();
                System.out.println("Using: " + cmd[0]);
                return Optional.of(cmd[0]);
            } catch (Exception ignored) {
            }
        }

        //System.out.println("No suitable commands found");
        return Optional.empty();
    }

    private static boolean chmod(Path file) {
        try {
            return Runtime.getRuntime().exec(new String[] {"chmod", "+x", file.toString()}).waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static void execMac(String home, String bin, String... args) {
        try {
            //Path file = writeLinesToFile(home, "start.command","#!/usr/bin/env bash", "", "echo \"Authorized\"", "#tput reset", "sudo " + bin + (args.length != 0 ? " " + String.join(" ", args) : ""));
            Path file = writeLinesToFile(home, "start.command","#!/usr/bin/env bash", "", bin + (args.length != 0 ? " " + String.join(" ", args) : ""));
            chmod(file);
            //Runtime.getRuntime().exec(new String[] {"osascript", "-e", "'tell application \"Terminal\" to do shell script \"" + file + "\" with administrator privileges'"}).waitFor();
            Runtime.getRuntime().exec(new String[] {"open", "-F", file.toString()}).waitFor();
            //Runtime.getRuntime().exec(new String[] {"rm", "~/start.sh"}).waitFor();
        } catch (InterruptedException | IOException e) {
            e.printStackTrace();
        }

    }

    public static Path writeLinesToFile(String base_dir, String filename, String... lines) throws IOException {
        Path file = FileSystems.getDefault().getPath(base_dir, filename);
        Files.write(file, Arrays.asList(lines), StandardCharsets.UTF_8);
        return file;
    }

}
