package com.satori.swing;

import com.satori.Execute;

import javax.swing.*;
import java.awt.*;

public class Progress extends JFrame {

    private static final Dimension SIZE = new Dimension(450, 80);
    private static final Color COLOR = new Color(139, 113, 181);
    private static final String TITLE_BASE = "SatoriNET| Launcher";
    private JProgressBar bar;

    private Progress() {
        super();

        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setLayout(null);
        this.setSize(SIZE);
        this.setLocationRelativeTo(null);
        this.setAlwaysOnTop(true);
        this.setResizable(false);
        this.setTitle(TITLE_BASE);
        this.setIconImage(new ImageIcon(getClass().getResource("/icon.png")).getImage());

        bar = new JProgressBar();
        bar.setIndeterminate(true);
        bar.setLocation(0,0);
        bar.setSize(SIZE);
        bar.setForeground(COLOR);

        this.add(bar);

        this.setVisible(true);
    }

    public static void startInstance() {
        SwingUtilities.invokeLater(() -> {
            Progress instance = new Progress();
            SwingWorker worker = new SwingWorker<Void, Integer>() {
                @Override
                protected Void doInBackground() {
                    Execute.startUpdater(instance);
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
