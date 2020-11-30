package com.satori;

import com.satori.console.Console;
import com.satori.swing.Progress;

import javax.swing.*;
import java.awt.*;

public interface Displayable {
    void endInstance();
    void endInstanceAndShowMessage(String text);
    void setProgressLength(int length);
    void tickProgressBar(int value);
    void updateTitle(String value);
    void setProgressIndeterminate(boolean val);
    boolean isGUI();
    static void startInstance(String... args) {
        try {
            // sometimes, there will be a non-graphical environment
            // this will throw an error if it cannot launch
            Desktop.getDesktop();
        } catch (Exception ignored) {
            System.out.println("Executing for a non-graphical environment");
            Execute.startUpdater(new Console(), args);
            return;
        }

        SwingUtilities.invokeLater(() -> {
            Progress instance = new Progress();
            SwingWorker<Void, Integer> worker = new SwingWorker<Void, Integer>() {
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
}
