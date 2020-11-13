/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.satori.util;

import java.awt.Image;
import javax.swing.ImageIcon;
import javax.swing.JComponent;

/**
 *
 * @author tbrau
 */
public class ImageUtils {
    public static <T extends JComponent> ImageIcon scaleImageTo(String resource, T component) {
        return new ImageIcon(new ImageIcon(component.getClass().getResource(resource)).getImage().getScaledInstance(component.getWidth(), component.getHeight(), Image.SCALE_DEFAULT));
    }
}
