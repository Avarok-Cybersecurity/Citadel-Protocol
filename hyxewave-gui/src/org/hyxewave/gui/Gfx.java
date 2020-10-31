/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

package org.hyxewave.gui;

import java.awt.*;

public class Gfx {

    private static AlphaComposite transparent = AlphaComposite.getInstance(AlphaComposite.SRC_OVER, VirtualDesktop.transparency);
    private static AlphaComposite opaque = AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 1.0f);
    private static int icon_size = 32;

    public static void drawShadow(Graphics2D g, int x, int y, int width, int height, boolean inner_shadow, boolean bilateral_shadow, int steps, Color startColor, Color endColor) {
        var r_stride = (endColor.getRed() - startColor.getRed()) / steps;
        var g_stride = (endColor.getGreen() - startColor.getGreen()) / steps;
        var b_stride = (endColor.getBlue() - startColor.getBlue()) / steps;
        var a_stride = (endColor.getAlpha() - startColor.getAlpha()) / steps;
        g.setStroke(new BasicStroke(1));
        for (int i = 0; i < steps; i++) {
            Color current = new Color(startColor.getRed() + i * r_stride, startColor.getGreen() + i * g_stride, startColor.getBlue() + i * b_stride, startColor.getAlpha() + i * a_stride);
            g.setColor(current);

            if (bilateral_shadow) {
                var x_coord_inner = i + x;
                var y_coord_inner = i + y;
                var width_inner = width - 2 * i;
                var height_inner = height - 2 * i;

                var x_coord_outer = x - i;
                var y_coord_outer = y - i;
                var width_outer = width + 2 * i;
                var height_outer = height + 2 * i;

                g.drawRect(x_coord_inner, y_coord_inner, width_inner, height_inner);
                g.drawRect(x_coord_outer, y_coord_outer, width_outer, height_outer);
                continue;
            }

            if (inner_shadow) {
                var x_coord_inner = i + x;
                var y_coord_inner = i + y;
                var width_inner = width - 2 * i;
                var height_inner = height - 2 * i;
                g.drawRect(x_coord_inner, y_coord_inner, width_inner, height_inner);
                continue;
            }

            if (!inner_shadow) {
                var x_coord_outer = x - i;
                var y_coord_outer = y - i;
                var width_outer = width + 2 * i;
                var height_outer = height + 2 * i;
                g.drawRect(x_coord_outer, y_coord_outer, width_outer, height_outer);
                continue;
            }

        }
    }

    public static void drawShadowedBox(Graphics2D g, Point startPoint, Point endPoint, Color border, Color inner) {
        //draw inner box first
        var width = endPoint.x - startPoint.x;
        var height = endPoint.y - startPoint.y;
        Polygon poly = new Polygon();
        poly.addPoint(startPoint.x, startPoint.y);
        poly.addPoint(startPoint.x + width, startPoint.y);
        poly.addPoint(endPoint.x, endPoint.y);
        poly.addPoint(startPoint.x, endPoint.y);

        g.setColor(inner);
        g.fillPolygon(poly);

        //now, draw shadowing
        drawShadow(g, startPoint.x, startPoint.y, width, height, true, false, 3, border, inner);
    }

    public static void drawShadowedBox(Graphics2D g, Point startPoint, Point endPoint, Color border, Color inner, int steps) {
        //draw inner box first
        var width = endPoint.x - startPoint.x;
        var height = endPoint.y - startPoint.y;
        Polygon poly = new Polygon();
        poly.addPoint(startPoint.x, startPoint.y);
        poly.addPoint(startPoint.x + width, startPoint.y);
        poly.addPoint(endPoint.x, endPoint.y);
        poly.addPoint(startPoint.x, endPoint.y);

        g.setColor(inner);
        g.fillPolygon(poly);

        //now, draw shadowing
        drawShadow(g, startPoint.x, startPoint.y, width, height, true, false, steps, border, inner);
    }

    public static void drawButton(Graphics2D g, Image icon, String label, Point topLeft, Point bottomRight, Color border, Color background, Color foreground, boolean pressed) {
        //draw box
        g.setComposite(transparent);
        drawShadowedBox(g, topLeft, bottomRight, border, background);

        g.setComposite(opaque);
        //draw icon (48x48)
        var point = getOptimalIconPosition(icon_size, topLeft, bottomRight);
        g.drawImage(icon, point.x - (icon_size * 2), (int) (point.y - (icon_size / 1.8)), null);

        //draw string
        g.setFont(new Font("Sans Serif", Font.BOLD, 16));
        g.setColor(foreground);

        g.drawString(label, point.x, point.y + 5);
    }

    private static Point getOptimalIconPosition(int size, Point topLeft, Point bottomRight) {
        var x = topLeft.x + ((bottomRight.x - topLeft.x) / 3) - size;
        var y = topLeft.y + ((bottomRight.y - topLeft.y) / 3) + (size / 3);
        return new Point(x, y);
    }

}
