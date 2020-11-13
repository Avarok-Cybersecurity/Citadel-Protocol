package com.satori.swing;

import com.satori.Execute;

import javax.swing.*;
import java.awt.*;

public class Progress extends JFrame {

    private static final Dimension SIZE = new Dimension(271, 40 + 271); // 450x80 = old
    private static final Color COLOR = new Color(139, 113, 181);
    private static final Color BAR_BG = new Color(255, 255, 255, 226);
    private static final String TITLE_BASE = "SatoriNET| Launcher";
    private JProgressBar bar;
    private JLabel description;

    private Progress() {
        super();

        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setLayout(null);
        this.setSize(SIZE);
        this.setUndecorated(true);
        this.setLocationRelativeTo(null);
        this.setAlwaysOnTop(true);
        this.setResizable(false);
        this.setTitle(TITLE_BASE);
        this.setIconImage(new ImageIcon(getClass().getResource("/icon.png")).getImage());

        JLabel zen = new JLabel();
        zen.setLocation(0,0);
        zen.setSize(271,271);
        zen.setIcon(new ImageIcon(getClass().getResource("/zen.png")));
        this.add(zen);

        description = new JLabel("Connecting ...");
        this.add(description);

        bar = new JProgressBar();
        bar.setIndeterminate(true);
        bar.setLocation(0,271);
        bar.setSize(271, 40);
        bar.setForeground(COLOR);
        bar.setBackground(BAR_BG);
        this.add(bar);

        this.setVisible(true);
    }

    public static void startInstance(String... args) {
        SwingUtilities.invokeLater(() -> {
            Progress instance = new Progress();
            SwingWorker worker = new SwingWorker<Void, Integer>() {
                @Override
                protected Void doInBackground() {
                    Execute.startUpdater(instance, args);
                    return null;
                }
            };

            worker.addPropertyChangeListener(event -> {
                if ("state".equals(event.getPropertyName())
                        && SwingWorker.StateValue.DONE == event.getNewValue()) {
                    instance.endInstance();
                }
            });

            worker.execute();
        });
    }

    public void endInstance() {
        this.setVisible(false);
        this.dispose();
    }

    public void endInstanceAndShowDialog(String msg) {
        this.endInstance();
        JOptionPane.showMessageDialog(null, msg);
    }

    public void setProgressLength(int length) {
        this.bar.setMaximum(length);
    }

    public void tickProgressBar(int newLen) {
        this.bar.setValue(newLen);
    }

    public void setProgressIndeterminate(boolean val) {
        this.bar.setIndeterminate(val);
    }

    public void updateTitle(String status) {
        this.setTitle(TITLE_BASE + " (" + status + ") ...");
    }

}
