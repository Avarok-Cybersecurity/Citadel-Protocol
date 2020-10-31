package com.lusna.util;

import java.util.function.Supplier;

public class ExponentialBackoffTracker {
    private Supplier<Boolean> function;
    private int currentValue;
    private int stopValue;
    private boolean succeeded = false;

    /// `stopValue`: This will stop executing the function once the internal value reaches stopValue
    public ExponentialBackoffTracker(int startValue, int stopValue, Supplier<Boolean> function) {
        this.function = function;
        this.currentValue = startValue;
        this.stopValue = stopValue;
    }

    /// Returns true if complete (whether successful or not. Must call this.didSucceed())
    /// Calling this after a true return is not recommended
    public boolean revolution() {
        if (!this.function.get()) {
            final int multiplier = 2;
            this.currentValue *= multiplier;
            System.out.println("[ExponentialBackoffTracker] Current Value: " + this.currentValue);
            return currentValue >= this.stopValue;
        } else {
            this.succeeded = true;
            System.out.println("[ExponentialBackoffTracker] Complete");
            return true;
        }
    }

    public boolean didSucceed() {
        return this.succeeded;
    }

    public int getCurrentValue() {
        return this.currentValue;
    }

    public boolean isFinished() {
        return this.currentValue >= this.stopValue || this.succeeded;
    }
}
