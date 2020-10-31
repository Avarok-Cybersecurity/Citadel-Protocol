/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.hyxewave.gui;

import io.vertx.core.Vertx;
import org.hyxewave.util.Constants;
import org.hyxewave.util.DaemonParser;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;

//import javafx.application.Platform;


public class VirtualDesktop extends JDesktopPane {


    public static HashMap<String, VirtualDesktop> LOCAL_SESSIONS = new HashMap();
    public static Icon TAB_ICON = new ImageIcon(new ImageIcon(Constants.TAB_SESSION).getImage().getScaledInstance(32, 32, Image.SCALE_SMOOTH));
    public static Image MENU_ICON_MESSAGE = new ImageIcon(new ImageIcon(Constants.MENU_MESSAGE).getImage().getScaledInstance(32, 32, Image.SCALE_SMOOTH)).getImage();
    public static Image MENU_ICON_FILE_BROWSER = new ImageIcon(new ImageIcon(Constants.MENU_HOME).getImage().getScaledInstance(32, 32, Image.SCALE_SMOOTH)).getImage();
    public static Image MENU_ICON_SETTINGS = new ImageIcon(new ImageIcon(Constants.MENU_SETTINGS).getImage().getScaledInstance(32, 32, Image.SCALE_SMOOTH)).getImage();
    public static Image MENU_ICON_ENCRYPT = new ImageIcon(new ImageIcon(Constants.MENU_ENCRYPT).getImage().getScaledInstance(32, 32, Image.SCALE_SMOOTH)).getImage();
    public static Image MENU_ICON_TERMINAL = new ImageIcon(new ImageIcon(Constants.MENU_TERMINAL).getImage().getScaledInstance(32, 32, Image.SCALE_SMOOTH)).getImage();
    public static Image MENU_ICON_LOGOUT = new ImageIcon(new ImageIcon(Constants.MENU_LOGOUT).getImage().getScaledInstance(32, 32, Image.SCALE_SMOOTH)).getImage();

    public static Image HYXEWAVE_LOGO_BG = Toolkit.getDefaultToolkit().getImage(Constants.HYXEWAVE_LOGO);
    public static float transparency = 0.7f;
    private static int menuHeight = 450;
    private final String sessionID;
    private final JTabbedPane pane;
    private final Vertx vertx;
    private boolean isFlashing = false;
    private JPanel bottomBar;
    private JButton menuButton;
    private boolean menuButtonHovered = false;
    private String time;
    private boolean isDragging = false;
    private Point dragStart = new Point();
    private Point dragEnd = new Point();
    private Color select_color = new Color(255, 165, 0, 100);

    private int bottomBarHeight = 40;
    private int menuButtonHeight = 40;
    private int menuButtonWidth = 140;
    private boolean menuButtonPressed = false;
    private boolean menuAreaHovered = false;
    private boolean menuAreaClicked = false;
    private boolean menuOpen = false;
    private Color menu_color = new Color(228, 243, 253, 180);
    private Color menu_button_background = new Color(29, 29, 29);
    private int menuItemHeight = 48;
    private int menuWidth = (int) (menuButtonWidth * 2.5);
    private Polygon menuButtonPoly;
    //Expanded menu options
    private Polygon menuPoly;
    private Polygon messageButtonPoly;
    private boolean messageButtonHovered = false;
    private Polygon fileBrowserPoly;
    private boolean fileBrowserButtonHovered;
    private boolean settingsButtonHovered = false;
    private Polygon settingsButtonPoly;
    private boolean encryptButtonHovered = false;
    private Polygon encryptButtonPoly;
    private boolean terminalButtonHovered = false;
    private Polygon terminalButtonPoly;
    private boolean logoutButtonHovered = false;
    private Polygon logoutButtonPoly;
    private Color green_default = new Color(53, 130, 20);
    private Color logout_bg = new Color(165, 28, 28);
    private boolean hasSetPolygons = false;
    private boolean msgDialogueExists = false;
    private long lastKeepAlive = -1;
    private long timerID = -1;

    public VirtualDesktop(String sessionID, JTabbedPane pane, Vertx vertx) {

        if (sessionID == null) sessionID = "Development";

        this.sessionID = sessionID;
        VirtualDesktop.LOCAL_SESSIONS.put(sessionID, this);
        pane.addTab(sessionID, TAB_ICON, this);

        this.pane = pane;

        if (vertx == null) vertx = Vertx.vertx();
        this.vertx = vertx;

        this.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {
                System.out.println("CLICKED at " + e.getPoint());
                dragStart = e.getPoint();

                if (isFlashing) {
                    flashTab(false);
                }

                menuButtonPressed = menuButtonPoly.contains(e.getPoint());
                menuAreaClicked = menuPoly.contains(e.getPoint()) && menuOpen;
                System.out.println("menuAreaClicked = " + menuAreaClicked);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                isDragging = false;
                dragStart = null;
                dragEnd = null;

                repaint();
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });

        this.addMouseMotionListener(new MouseMotionListener() {
            @Override
            public void mouseDragged(MouseEvent e) {
                dragEnd = e.getPoint();
                isDragging = true;
                //System.out.println("[Dragging] x " + e.getX() + " y " + e.getY());
                mouseMoved(e);
            }

            @Override
            public void mouseMoved(MouseEvent e) {
                var x = e.getX();
                var y = e.getY();

                //System.out.println( x + ", " + y + " [" + menuButtonWidth + ", " + getHeight() + "]");
                if (x <= menuButtonWidth && y >= getHeight() - bottomBarHeight) {
                    menuButtonHovered = true;
                    //System.out.println("HERE");
                    repaint();
                    return;
                }

                menuButtonHovered = false;
                menuAreaHovered = menuPoly.contains(e.getPoint()) && menuButtonPressed;
                messageButtonHovered = messageButtonPoly.contains(e.getPoint());
                fileBrowserButtonHovered = fileBrowserPoly.contains(e.getPoint());
                settingsButtonHovered = settingsButtonPoly.contains(e.getPoint());
                encryptButtonHovered = encryptButtonPoly.contains(e.getPoint());
                terminalButtonHovered = terminalButtonPoly.contains(e.getPoint());
                logoutButtonHovered = logoutButtonPoly.contains(e.getPoint());

                repaint();
            }
        });


        this.pane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                super.componentResized(e);
                //update polygons
                setupPolygons();
            }
        });

        this.vertx.setPeriodic(1000, (id) -> {
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HH:mm");
            LocalDateTime now = LocalDateTime.now();
            this.time = dtf.format(now);
        });

        initComponents();
    }

    public static VirtualDesktop getVirtualDesktopBySID(String sid) {
        return LOCAL_SESSIONS.get(sid);
    }

    private void initComponents() {
        this.setLayout(null);

        var bg_color = new Color(50, 84, 112);
        this.setBackground(bg_color);
        //this.setVisible(true);

    }

    private void setupPolygons() {
        var desktopHeight = this.getHeight();
        menuButtonPoly = new Polygon();
        menuButtonPoly.addPoint(0, desktopHeight - menuButtonHeight);
        menuButtonPoly.addPoint(menuButtonWidth, desktopHeight - menuButtonHeight);
        menuButtonPoly.addPoint(menuButtonWidth, desktopHeight);
        menuButtonPoly.addPoint(0, desktopHeight);

        menuPoly = new Polygon();
        menuPoly.addPoint(0, desktopHeight - menuButtonHeight - menuHeight);
        menuPoly.addPoint(menuWidth, desktopHeight - menuButtonHeight - menuHeight);
        menuPoly.addPoint(menuWidth, desktopHeight - menuButtonHeight - 2);
        menuPoly.addPoint(0, desktopHeight - menuButtonHeight - 2);

        messageButtonPoly = new Polygon();
        //new Point(menuPoly.xpoints[0], menuPoly.ypoints[0]), new Point(menuPoly.xpoints[1], menuPoly.ypoints[0] + 48)
        messageButtonPoly.addPoint(menuPoly.xpoints[0], menuPoly.ypoints[0]);
        messageButtonPoly.addPoint(menuPoly.xpoints[1], menuPoly.ypoints[0]);
        messageButtonPoly.addPoint(menuPoly.xpoints[1], menuPoly.ypoints[0] + menuItemHeight);
        messageButtonPoly.addPoint(menuPoly.xpoints[0], menuPoly.ypoints[0] + menuItemHeight);

        fileBrowserPoly = new Polygon();
        fileBrowserPoly.addPoint(messageButtonPoly.xpoints[0], messageButtonPoly.ypoints[0] + menuItemHeight);
        fileBrowserPoly.addPoint(messageButtonPoly.xpoints[1], messageButtonPoly.ypoints[0] + menuItemHeight);
        fileBrowserPoly.addPoint(messageButtonPoly.xpoints[1], messageButtonPoly.ypoints[2] + menuItemHeight);
        fileBrowserPoly.addPoint(messageButtonPoly.xpoints[0], messageButtonPoly.ypoints[2] + menuItemHeight);

        settingsButtonPoly = new Polygon();
        settingsButtonPoly.addPoint(fileBrowserPoly.xpoints[0], fileBrowserPoly.ypoints[0] + menuItemHeight);
        settingsButtonPoly.addPoint(fileBrowserPoly.xpoints[1], fileBrowserPoly.ypoints[0] + menuItemHeight);
        settingsButtonPoly.addPoint(fileBrowserPoly.xpoints[1], fileBrowserPoly.ypoints[2] + menuItemHeight);
        settingsButtonPoly.addPoint(fileBrowserPoly.xpoints[0], fileBrowserPoly.ypoints[2] + menuItemHeight);

        encryptButtonPoly = new Polygon();
        encryptButtonPoly.addPoint(settingsButtonPoly.xpoints[0], settingsButtonPoly.ypoints[0] + menuItemHeight);
        encryptButtonPoly.addPoint(settingsButtonPoly.xpoints[1], settingsButtonPoly.ypoints[0] + menuItemHeight);
        encryptButtonPoly.addPoint(settingsButtonPoly.xpoints[1], settingsButtonPoly.ypoints[2] + menuItemHeight);
        encryptButtonPoly.addPoint(settingsButtonPoly.xpoints[0], settingsButtonPoly.ypoints[2] + menuItemHeight);

        terminalButtonPoly = new Polygon();
        terminalButtonPoly.addPoint(encryptButtonPoly.xpoints[0], encryptButtonPoly.ypoints[0] + menuItemHeight);
        terminalButtonPoly.addPoint(encryptButtonPoly.xpoints[1], encryptButtonPoly.ypoints[0] + menuItemHeight);
        terminalButtonPoly.addPoint(encryptButtonPoly.xpoints[1], encryptButtonPoly.ypoints[2] + menuItemHeight);
        terminalButtonPoly.addPoint(encryptButtonPoly.xpoints[0], encryptButtonPoly.ypoints[2] + menuItemHeight);

        //Bottom of menu now
        logoutButtonPoly = new Polygon();
        logoutButtonPoly.addPoint(0, getHeight() - menuButtonHeight - menuItemHeight);
        logoutButtonPoly.addPoint(menuWidth, getHeight() - menuButtonHeight - menuItemHeight);
        logoutButtonPoly.addPoint(menuWidth, getHeight() - menuButtonHeight);
        logoutButtonPoly.addPoint(0, getHeight() - menuButtonHeight);

        hasSetPolygons = true;
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        if (!hasSetPolygons) {
            setupPolygons();
        }

        Graphics2D gfx = (Graphics2D) g;
        gfx.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        //draw background logo
        //HYXEWAVE_LOGO_BG = HYXEWAVE_LOGO_BG.getScaledInstance(getWidth(), getHeight(), Image.SCALE_SMOOTH);
        gfx.drawImage(HYXEWAVE_LOGO_BG, (getWidth() / 2) - (HYXEWAVE_LOGO_BG.getWidth(null) / 2), (getHeight() / 2) - (HYXEWAVE_LOGO_BG.getHeight(null) / 2), null);

        //draw bottom bar
        AlphaComposite transparent = AlphaComposite.getInstance(AlphaComposite.SRC_OVER, transparency);
        AlphaComposite opaque = AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 1.0f);
        gfx.setColor(menu_color);
        gfx.setComposite(transparent);
        gfx.fillRect(0, this.getHeight() - bottomBarHeight, this.getWidth(), bottomBarHeight);
        gfx.setComposite(opaque);

        //draw button
        gfx.setColor(menu_color.darker().darker());
        gfx.fillPolygon(menuButtonPoly);

        if (menuButtonHovered || menuButtonPressed || menuAreaHovered || menuAreaClicked) {
            gfx.setColor(new Color(53, 130, 20));
            gfx.fillPolygon(menuButtonPoly);
            Gfx.drawShadow(gfx, 0, this.getHeight() - bottomBarHeight, menuButtonWidth, bottomBarHeight, true, false, 4, menu_color.darker().darker(), new Color(53, 130, 20));
        }

        gfx.setColor(menu_color.darker().darker());
        gfx.setStroke(new BasicStroke(3));
        gfx.drawRect(0, this.getHeight() - bottomBarHeight, this.getWidth(), bottomBarHeight);

        gfx.setFont(new Font("Sans Serif", Font.BOLD, 30));
        if (this.time != null) {
            gfx.setColor(menu_color.darker().darker().darker());
            gfx.drawString(this.time, this.getWidth() - 85, this.getHeight() - 8);
        }

        gfx.setColor(menu_color);
        gfx.drawString("Start", 8, this.getHeight() - 8);


        if (menuButtonPressed || menuAreaClicked) {
            gfx.setComposite(transparent);
            Gfx.drawShadowedBox(gfx, new Point(menuPoly.xpoints[0], menuPoly.ypoints[0]), new Point(menuPoly.xpoints[2], menuPoly.ypoints[2]), menu_color.darker().darker(), menu_color);
            gfx.setComposite(opaque);


            Gfx.drawButton(gfx, MENU_ICON_MESSAGE, "Secure Messaging", new Point(menuPoly.xpoints[0], menuPoly.ypoints[0]), new Point(menuPoly.xpoints[1], menuPoly.ypoints[0] + menuItemHeight), menu_color.darker().darker()
                    , messageButtonHovered ? green_default : menu_button_background, menu_color, false);

            Gfx.drawButton(gfx, MENU_ICON_FILE_BROWSER, "File Browser", new Point(fileBrowserPoly.xpoints[0], fileBrowserPoly.ypoints[0]), new Point(fileBrowserPoly.xpoints[2], fileBrowserPoly.ypoints[2]), menu_color.darker().darker()
                    , fileBrowserButtonHovered ? green_default : menu_button_background, menu_color, false);

            Gfx.drawButton(gfx, MENU_ICON_SETTINGS, "Account Settings", new Point(settingsButtonPoly.xpoints[0], settingsButtonPoly.ypoints[0]), new Point(settingsButtonPoly.xpoints[2], settingsButtonPoly.ypoints[2]), menu_color.darker().darker()
                    , settingsButtonHovered ? green_default : menu_button_background, menu_color, false);

            Gfx.drawButton(gfx, MENU_ICON_ENCRYPT, "File Protector", new Point(encryptButtonPoly.xpoints[0], encryptButtonPoly.ypoints[0]), new Point(encryptButtonPoly.xpoints[2], encryptButtonPoly.ypoints[2]), menu_color.darker().darker()
                    , encryptButtonHovered ? green_default : menu_button_background, menu_color, false);

            Gfx.drawButton(gfx, MENU_ICON_TERMINAL, "Terminal", new Point(terminalButtonPoly.xpoints[0], terminalButtonPoly.ypoints[0]), new Point(terminalButtonPoly.xpoints[2], terminalButtonPoly.ypoints[2]), menu_color.darker().darker()
                    , terminalButtonHovered ? green_default : menu_button_background, menu_color, false);

            //bottom of menu
            Gfx.drawButton(gfx, MENU_ICON_LOGOUT, "Logout", new Point(logoutButtonPoly.xpoints[0], logoutButtonPoly.ypoints[0]), new Point(logoutButtonPoly.xpoints[2], logoutButtonPoly.ypoints[2]), menu_color.darker().darker()
                    , logoutButtonHovered ? logout_bg : menu_button_background, menu_color, false);

            menuOpen = true;
        } else {
            menuOpen = false;
        }

        if (isDragging) {
            var startPoint = dragStart;
            var endPoint = dragEnd;

            System.out.println("start: " + startPoint + " ||| end: " + endPoint);

            Gfx.drawShadowedBox(gfx, startPoint, endPoint, select_color.darker().darker(), select_color);
        }

        /*gfx.setColor(Color.RED);
        gfx.drawOval(fileBrowserPoly.xpoints[0], fileBrowserPoly.ypoints[0], 3, 3) ;
        gfx.drawOval(fileBrowserPoly.xpoints[1], fileBrowserPoly.ypoints[1], 3, 3) ;
        gfx.drawOval(fileBrowserPoly.xpoints[2], fileBrowserPoly.ypoints[2], 3, 3) ;
        gfx.drawOval(fileBrowserPoly.xpoints[3], fileBrowserPoly.ypoints[3], 3, 3) ;*/
        //super.paintComponent(g);
    }

    public String getSessionID() {
        return this.sessionID;
    }

    public void flashTab(boolean flash) {
        this.isFlashing = flash;
        if (flash) {
            //this.pane.flash(getTabIndex(), new Color(255, 255, 255), new Color(51, 85, 111));
        } else {
            //pane.clearFlashing();
        }
    }

    public void notifyDisconnect() {
        if (!msgDialogueExists)
            new Thread(() -> {
                msgDialogueExists = true;
                flashTab(true);
                JOptionPane.showInternalMessageDialog(this, "You are currently disconnected from the server. Please log-in again", "Server Disconnected", JOptionPane.ERROR_MESSAGE);
                int idx = this.getTabIndex();
                if (idx != -1) {
                    this.pane.removeTabAt(idx);
                }
                msgDialogueExists = false;
            }).start();
    }

    public void handleSignal(DaemonParser.DaemonPacket packet, Vertx vertx) {
        System.out.println("[VirtualDesktop] Received signal!");
        switch (packet.statusCode) {
            case Constants.DO_KEEP_ALIVE_SUCCESS:
                if (lastKeepAlive != -1) {
                    var now = System.currentTimeMillis();
                    var diff = now - lastKeepAlive;
                    if (diff >= Constants.TIMEOUT) {
                        System.err.println("[VirtualDesktop] TIMEOUT elapsed");
                        notifyDisconnect();
                        return;
                    }
                    lastKeepAlive = now;
                } else {
                    lastKeepAlive = System.currentTimeMillis();
                    this.vertx.setPeriodic(Constants.TIMEOUT, (obj) -> {
                        timerID = obj;
                        if (System.currentTimeMillis() - lastKeepAlive >= Constants.TIMEOUT) {
                            notifyDisconnect();
                            vertx.cancelTimer(obj);
                        }
                    });
                }
                break;


            case Constants.DO_KEEP_ALIVE_FAILURE:
                notifyDisconnect();
                vertx.cancelTimer(timerID);
                break;
            default:
                System.err.println("[VirtualDesktop] Invalid flag: " + packet.statusCode);
        }
    }

    private int getTabIndex() {
        return pane.indexOfTab(this.sessionID);
    }

}
