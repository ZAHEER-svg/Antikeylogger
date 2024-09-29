package com.example;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.HashMap;

import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.github.kwhat.jnativehook.GlobalScreen;
import com.github.kwhat.jnativehook.NativeHookException;
import com.github.kwhat.jnativehook.keyboard.NativeKeyEvent;
import com.github.kwhat.jnativehook.keyboard.NativeKeyListener;


public class KeyloggerDetector implements NativeKeyListener {

    private static final Logger LOGGER = Logger.getLogger(KeyloggerDetector.class.getName());
    private BufferedWriter logWriter;
    private File logFile;
    private boolean saveEnabled = false;
    private boolean isRunning = false;
    private Map<String, Integer> keyloggersMap;
    private JTextArea textArea;

    public KeyloggerDetector() {
        keyloggersMap = new HashMap<>();
        keyloggersMap.put("Keylogger1", 12345);
        keyloggersMap.put("Keylogger2", 67890);

        logFile = new File("C:\\Users\\USER\\OneDrive\\Desktop\\Anti-Key0\\keylog.txt");

        try {
            logWriter = new BufferedWriter(new FileWriter(logFile, true));
            saveEnabled = true;
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error initializing log writer.", e);
        }
    }

    public void startLogging() {
        if (isRunning) return;

        isRunning = true;
        new Thread(() -> {
            try {
                GlobalScreen.registerNativeHook();
                GlobalScreen.addNativeKeyListener(this);
            } catch (NativeHookException e) {
                LOGGER.log(Level.SEVERE, "Error registering native hook.", e);
            }
        }).start();
    }

    public void stopLogging() {
        if (!isRunning) return;

        isRunning = false;
        try {
            GlobalScreen.unregisterNativeHook();
        } catch (NativeHookException e) {
            LOGGER.log(Level.SEVERE, "Error unregistering native hook.", e);
        }
    }

    public void showGUI() {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Keylogger Detector");
            frame.setSize(600, 450);
            frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            frame.setLocationRelativeTo(null);
            frame.setResizable(false);

            // Initialize textArea
            textArea = new JTextArea(15, 40);
            textArea.setEditable(false);
            textArea.setFont(new Font("Consolas", Font.PLAIN, 14));
            textArea.setBackground(new Color(30, 30, 30));
            textArea.setForeground(Color.GREEN);
            textArea.setCaretColor(Color.WHITE);
            JScrollPane scrollPane = new JScrollPane(textArea);
            scrollPane.setBorder(BorderFactory.createLineBorder(new Color(60, 60, 60)));

            // Setting up buttons (with listeners)

            JButton saveKeyloggersButton = new JButton("Save Keyloggers");
            JButton loadKeystrokesButton = new JButton("Load Keystrokes");

            // Add buttons to panel
            JPanel buttonPanel = new JPanel();
            buttonPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 15, 10));
            buttonPanel.setBackground(new Color(44, 62, 80));

            buttonPanel.add(saveKeyloggersButton);
            buttonPanel.add(loadKeystrokesButton);

            // Setting up the main panel
            JPanel mainPanel = new JPanel(new BorderLayout());
            mainPanel.setBackground(new Color(44, 62, 80));
            mainPanel.add(scrollPane, BorderLayout.CENTER);
            mainPanel.add(buttonPanel, BorderLayout.SOUTH);

            // Final frame settings
            frame.add(mainPanel);
            frame.setVisible(true);

            // Register native hook and key listener
            try {
                GlobalScreen.registerNativeHook();
            } catch (NativeHookException ex) {
                Logger.getLogger(GlobalScreen.class.getPackage().getName()).setLevel(Level.WARNING);
                ex.printStackTrace();
                System.exit(1);
            }
            GlobalScreen.addNativeKeyListener(KeyloggerDetector.this);

            // Register shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(this::cleanup));
        });
    }

    private void toggleSave() {
        SwingUtilities.invokeLater(() -> {
            if (saveEnabled) {
                saveEnabled = false;
                JOptionPane.showMessageDialog(null, "Logging disabled.");
            } else {
                try {
                    logWriter = new BufferedWriter(new FileWriter(logFile, true));
                    saveEnabled = true;
                    JOptionPane.showMessageDialog(null, "Logging enabled to: " + logFile.getAbsolutePath());
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Error opening file for writing.", e);
                    JOptionPane.showMessageDialog(null, "Error opening file for writing.", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
    }

    private void logKeyStroke(String keyStroke) {
        if (saveEnabled && logWriter != null) {
            try {
                logWriter.write(keyStroke);
                logWriter.newLine();
                logWriter.flush();
                LOGGER.info("Logged: " + keyStroke + " to " + logFile.getAbsolutePath());
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Error writing keystroke to log.", e);
            }
        } else {
            LOGGER.info("Logging not enabled or logWriter is null");
        }
    }

    private void saveKeyloggersToFile() {
        SwingUtilities.invokeLater(() -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Specify a file to save keyloggers");
            int userSelection = fileChooser.showSaveDialog(null);
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                    if (keyloggersMap.isEmpty()) {
                        writer.write("No keyloggers found.");
                    } else {
                        for (Map.Entry<String, Integer> entry : keyloggersMap.entrySet()) {
                            writer.write("Keylogger: " + entry.getKey() + ", Process ID: " + entry.getValue());
                            writer.newLine();
                        }
                    }
                    JOptionPane.showMessageDialog(null, "Keyloggers saved successfully.");
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Error saving keyloggers.", e);
                    JOptionPane.showMessageDialog(null, "Error saving keyloggers.", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
    }

    private void loadAndDisplayKeystrokes(JTextArea textArea) {
        new Thread(() -> {
            if (logFile != null && logFile.exists()) {
                try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    SwingUtilities.invokeLater(() -> textArea.setText(sb.toString()));
                    System.out.println("Keystrokes loaded from: " + logFile.getAbsolutePath());
                } catch (IOException e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(null, "Error loading keystrokes.", "Error", JOptionPane.ERROR_MESSAGE);
                }
            } else {
                JOptionPane.showMessageDialog(null, "Log file does not exist.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }).start();
    }
    private void appendToTextArea(String text) {
        if (textArea != null) {
            SwingUtilities.invokeLater(() -> textArea.append(text + "\n"));
        } else {
            LOGGER.warning("textArea is null");
        }
    }


    @Override
    public void nativeKeyPressed(NativeKeyEvent e) {
        String keyText = NativeKeyEvent.getKeyText(e.getKeyCode());
        logKeystroke(keyText);
        appendToTextArea("Pressed: " + keyText);  // Update JTextArea with the pressed key
    }

    private synchronized void logKeystroke(String keyText) {
        if (saveEnabled && logWriter != null) {
            try {
                logWriter.write(keyText + "\n");
                logWriter.flush();
                LOGGER.info("Logged: " + keyText + " to " + logFile.getAbsolutePath());
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Error writing keystroke to log.", e);
                JOptionPane.showMessageDialog(null, "Error writing keystroke to log.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        } else {
            LOGGER.info("Logging not enabled or logWriter is null");
        }
    }

    @Override
    public void nativeKeyReleased(NativeKeyEvent e) {
        String keyStroke = "Released: " + NativeKeyEvent.getKeyText(e.getKeyCode());
        logKeystroke(keyStroke);
        appendToTextArea(keyStroke);
    }

    @Override
    public void nativeKeyTyped(NativeKeyEvent e) {
        // Get the character typed
        char typedChar = e.getKeyChar();

        // Log the character typed
        logKeystroke(String.valueOf(typedChar));

        // Append the typed character to the text area if it is initialized
        if (textArea != null) {
            SwingUtilities.invokeLater(() -> textArea.append("Typed: " + typedChar + "\n"));
        } else {
            LOGGER.warning("textArea is null - GUI might not be initialized yet.");
        }
    }

    private void closeLogWriter() {
        if (logWriter != null) {
            try {
                logWriter.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void cleanup() {
        closeLogWriter();
        try {
            GlobalScreen.unregisterNativeHook();
        } catch (NativeHookException e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            KeyloggerDetector detector = new KeyloggerDetector();
            Runtime.getRuntime().addShutdownHook(new Thread(detector::cleanup));
            detector.showGUI(); // Show GUI after adding shutdown hook
        });
    }
}
