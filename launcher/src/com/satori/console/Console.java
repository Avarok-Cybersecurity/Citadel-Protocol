package com.satori.console;

import com.satori.Displayable;

public class Console implements Displayable {
    private int maxLength = 0;
    private int ticks = 0;

    @Override
    public void endInstance() {
        // noop
    }

    @Override
    public void endInstanceAndShowMessage(String text) {
        System.out.println(text);
    }

    @Override
    public void setProgressLength(int length) {
        this.maxLength = length;
    }

    @Override
    public void tickProgressBar(int value) {
        this.ticks = value;
    }

    @Override
    public void updateTitle(String value) {
        // noop
    }

    @Override
    public void setProgressIndeterminate(boolean val) {
        // noop
    }

    @Override
    public boolean isGUI() {
        return false;
    }
}
