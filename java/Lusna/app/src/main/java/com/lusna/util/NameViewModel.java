package com.lusna.util;

import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;

public class NameViewModel extends ViewModel {

    // Create a LiveData with a String
    private MutableLiveData<String> currentName = new MutableLiveData<>();

    public MutableLiveData<String> getCurrentName() {
        if (currentName == null) {
            currentName = new MutableLiveData<>();
        }
        return currentName;
    }

    public static NameViewModel from(String init) {
        NameViewModel model = new NameViewModel();
        model.currentName = new MutableLiveData<>(init);
        return model;
    }

    public void setText(String newText, boolean post) {
        if (post) {
            this.currentName.postValue(newText);
        } else {
            this.currentName.setValue(newText);
        }
    }

    public void appendText(String append, char divider, boolean post) {
        String current_value = this.currentName.getValue();
        String newValue = current_value + divider + append;
        this.setText(newValue, post);
    }

    public void refresh() {
        this.currentName.setValue(this.currentName.getValue());
    }

    public String getValue() {
        return this.currentName.getValue();
    }
}