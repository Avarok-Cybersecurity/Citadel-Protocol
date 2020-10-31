package com.example.lusna.ui;

import android.os.Bundle;

import java.util.Optional;

public class GlobalFragmentBundle {
    private Bundle bundle;
    public GlobalFragmentBundle() {
        this.bundle = new Bundle();
    }

    public void insert(String fragmentTag, String keyTag, String entry) {
        Bundle fragmentBundle = this.bundle.getBundle(fragmentTag);
        if (fragmentBundle == null) {
            Bundle newBundle = new Bundle();
            newBundle.putString(keyTag, entry);
            this.bundle.putBundle(fragmentTag, newBundle);
        } else {
            fragmentBundle.putString(keyTag, entry);
        }
    }

    public Optional<String> tryGetValue(String fragmentTag, String keyTag) {
        Bundle fragmentBundle = this.bundle.getBundle(fragmentTag);
        if (fragmentBundle != null) {
            String value = fragmentBundle.getString(keyTag);
            if (value != null) {
                return Optional.of(value);
            }
        }

        return Optional.empty();
    }

    public void appendToEntry(String fragmentTag, String keyTag, String append, char divider) {
        Bundle fragmentBundle = this.bundle.getBundle(fragmentTag);
        if (fragmentBundle == null) {
            this.insert(fragmentTag, keyTag, append);
        } else {
            String current_value = fragmentBundle.getString(keyTag);
            if (current_value != null) {
                String newValue = current_value + divider + append;
                fragmentBundle.putString(keyTag, newValue);
            } else {
                fragmentBundle.putString(keyTag, append);
            }
        }
    }
}
