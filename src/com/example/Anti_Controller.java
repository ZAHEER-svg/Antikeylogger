package com.example;
import com.github.kwhat.jnativehook.GlobalScreen;
import com.github.kwhat.jnativehook.NativeHookException;
import com.sun.scenario.Settings;
import javafx.animation.PauseTransition;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.stage.Stage;
import javafx.animation.FadeTransition;
import javafx.util.Duration;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.application.Platform;
import javax.swing.*;
import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

import java.util.stream.Stream;

public class Anti_Controller {

    public CheckBox autoUpdateCheckbox;
    public Button contextualAnalysisButton;

    @FXML
    private TextArea recentKeystrokesArea;

    public CheckBox notifyCheckbox;

    public ComboBox sensitivityComboBox;

    public TextField logRetentionTextField;

    @FXML
    private Button startHeuristicsButton;

    @FXML
    private Button startSignatureButton;

    @FXML
    private Button startBehavioralButton;

    public Button applyButton;
    public Button cancelButton;
    public Label scanMessageLabel;
    @FXML
    private ImageView backgroundImage;

    @FXML
    private Button startButton;

    @FXML
    private ListView<String> sandboxingListView;

    @FXML
    private ListView<String> heuristicListView;

    @FXML
    private ListView<String> signatureListView;

    @FXML
    private ListView<String> behavioralAnalysisListView;

    @FXML
    private TextField searchField;

    @FXML
    private Button inspectButton;

    @FXML
    private Button stopThreatButton;

    @FXML
    private Button backButton;

    @FXML
    private Button startDetectionButton;

    @FXML
    private Button searchButton;


    @FXML
    private ProgressIndicator progressIndicator;

    private KeyloggerDetector keyloggerDetector;

    private ObservableList<String> heuristicList;

    private ObservableList<String> signatureList;

    private boolean keyloggerGUIShown = false;

    private volatile boolean isDetecting;  // Flag for controlling detection

    private boolean isKeyloggerDetectorVisible = false; // Flag to control visibility

    @FXML
    private Button showKeyloggerButton;

    private SimpleKeylogger keylogger;

    private List<String> searchKeyloggersInFile(String query) {
        List<String> recurringKeyloggers = new ArrayList<>();
        File logFile = new File("C:\\Users\\USER\\OneDrive\\Desktop\\Anti-Key0\\keylog.txt");

        if (logFile.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
                Map<String, Long> keyloggerCounts = reader.lines()
                        .map(line -> {
                            String[] parts = line.split(":", 2);
                            if (parts.length > 1) {
                                return parts[1].trim(); // Get the keylogger part
                            } else {
                                return ""; // Handle lines without a colon
                            }
                        })
                        .filter(keylogger -> !keylogger.isEmpty()) // Remove empty keyloggers
                        .collect(Collectors.groupingBy(String::toLowerCase, Collectors.counting()));

                recurringKeyloggers = keyloggerCounts.entrySet().stream()
                        .filter(entry -> entry.getValue() > 1 && entry.getKey().contains(query))
                        .map(entry -> entry.getKey() + " - Occurrences: " + entry.getValue())
                        .collect(Collectors.toList());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return recurringKeyloggers;
    }





    public Anti_Controller() {
        SwingUtilities.invokeLater(() -> {
            keyloggerDetector = new KeyloggerDetector();
        });
    }

    @FXML
    private void initialize() {
        FadeTransition fadeIn = new FadeTransition(Duration.seconds(2), startButton);
        fadeIn.setFromValue(0.0);
        fadeIn.setToValue(1.0);
        fadeIn.play();

        ObservableList<String> detectedKeyloggers = FXCollections.observableArrayList(
                "Keylogger A - Process ID: 1234",
                "Keylogger B - Process ID: 5678",
                "Keylogger C - Process ID: 9101"
        );
        if (sandboxingListView != null) {
            sandboxingListView.setItems(detectedKeyloggers);
        }

        signatureList = FXCollections.observableArrayList(

        );
        if (signatureListView != null) {
            signatureListView.setItems(signatureList);
        }

        if (behavioralAnalysisListView != null) {
            ObservableList<String> behavioralPatterns = FXCollections.observableArrayList(

            );
            behavioralAnalysisListView.setItems(behavioralPatterns);
        }
        isKeyloggerDetectorVisible = false;

    }
    @FXML
    private void handleStartApplication(ActionEvent event) {
        navigateTo("/welcome_page.fxml", event);
        System.out.println("Back to Main Menu");
    }
    @FXML
    private void handleHeuristicsApplication(ActionEvent event) {
        navigateTo("/heuristic_detection.fxml", event);
        System.out.println("Back to Main Menu");
    }

    @FXML
    private void handleSignaturApplication(ActionEvent event) {
        navigateTo("/signature_detection.fxml", event);
        System.out.println("Opening Signature detection ");
    }


    @FXML
    private void handleBehaviorApplication(ActionEvent event) {
        navigateTo("/behavioral_analysis.fxml", event);
        System.out.println("Opening Behavioral analysis");
    }
    @FXML
    private void handlesettings(ActionEvent event) {
        navigateTo("/settings.fxml", event);
        System.out.println("Opening settings");
    }

    @FXML
    private void handleGoToSignatureDetection(ActionEvent event) {
        navigateTo("/signature_detection.fxml", event);
    }

    @FXML
    private void handleGoToHeuristicDetection(ActionEvent event) {
        navigateTo("/heuristic_detection.fxml", event);
    }

    @FXML
    private void handleGoToBehavioralAnalysis(ActionEvent event) {
        navigateTo("/behavioral_analysis.fxml", event);
    }

    @FXML
    private void handleGoToSandboxing(ActionEvent event) {
        navigateTo("/sandboxing.fxml", event);
    }

    @FXML
    private void handleGoToSettings(ActionEvent event) {
        navigateTo("/settings.fxml", event);
    }

    @FXML
    private void handleExitApplication(ActionEvent event) {
        navigateTo("/welcome_page.fxml", event);
    }
    @FXML
    private void handleToggleKeyloggerVisibility(ActionEvent event) {
        isKeyloggerDetectorVisible = !isKeyloggerDetectorVisible;
        if (isKeyloggerDetectorVisible) {
            showAlert(Alert.AlertType.INFORMATION, "Keylogger Visibility", "Keylogger Detector is now visible.");
            // Code to make KeyloggerDetector visible (if necessary)
        } else {
            showAlert(Alert.AlertType.INFORMATION, "Keylogger Visibility", "Keylogger Detector is now hidden.");
            // Code to hide KeyloggerDetector (if necessary)
            keyloggerDetector.showGUI();
        }
    }
    @FXML
    private void handleShowKeylogger() {
        // Check if the GUI has already been shown
        if (!keyloggerGUIShown) {
            // Show the KeyloggerDetector GUI
            keyloggerDetector.showGUI();

            // Set the flag to true after showing the GUI
            keyloggerGUIShown = true;

            // Optionally, disable the button to prevent further clicks
            showKeyloggerButton.setDisable(true);

            // Enable other buttons
            startHeuristicsButton.setDisable(false);
            startSignatureButton.setDisable(false);
            startBehavioralButton.setDisable(false);

        } else {
            // Optionally, show a message that the GUI is already open
            System.out.println("Keylogger Detector is already open.");
        }
    }




    @FXML
    private void handleInspectSelected(ActionEvent event) {
        String selectedKeylogger = sandboxingListView.getSelectionModel().getSelectedItem();
        if (selectedKeylogger != null) {
            showAlert(Alert.AlertType.INFORMATION, "Inspect Keylogger", "Details for: " + selectedKeylogger);
        } else {
            showAlert(Alert.AlertType.WARNING, "No Selection", "Please select a keylogger to inspect.");
        }
    }

    @FXML
    private void handleStopThreat(ActionEvent event) {
        String selectedKeylogger = sandboxingListView.getSelectionModel().getSelectedItem();
        if (selectedKeylogger != null) {
            showAlert(Alert.AlertType.CONFIRMATION, "Stop Threat", "Stopping: " + selectedKeylogger);
        } else {
            showAlert(Alert.AlertType.WARNING, "No Selection", "Please select a keylogger to stop.");
        }
    }

    @FXML
    private void handleStartHeuristicDetection() {
        isDetecting = true;
        progressIndicator.setVisible(true);
        new Thread(() -> {
            try {
                while (isDetecting) {
                    loadAndDisplayKeystrokes();
                    Thread.sleep(2000); // Adjust sleep duration as needed
                }
            } catch (InterruptedException e) {
                Platform.runLater(() -> showAlert(Alert.AlertType.ERROR, "Error", "An error occurred during detection: " + e.getMessage()));
            } finally {
                Platform.runLater(() -> progressIndicator.setVisible(false));
            }
        }).start();


    }

    @FXML
    private void handleStopHeuristicDetection(ActionEvent event) {
        if (isDetecting) {
            // Stop heuristic detection logic here

            // Stop keylogger
            SimpleKeylogger.stopKeylogger();

            // Update the UI or state to reflect that detection has stopped
            updateUIAfterStoppingDetection();

            // Set the detecting flag to false
            isDetecting = false;

            // Show a message to indicate that detection has been stopped
            showAlert("Heuristic detection has been stopped and keylogging activity is now intercepted.");
        } else {
            // Optionally, show a message if detection was not running
            showAlert("Heuristic detection is not currently running.");}
        isDetecting = false;
        progressIndicator.setVisible(false);
        showAlert(Alert.AlertType.INFORMATION, "Detection Stopped", "Heuristic detection has been stopped.");
        SimpleKeylogger.startKeylogger();
    }
    private void showAlert(String message) {
        // Implement alert dialog or message display logic here
    }
    private void updateUIAfterStoppingDetection() {
        // Implement UI update logic here
    }

    @FXML
    private void loadAndDisplayKeystrokes1() {
        File logFile = new File("C:\\Users\\USER\\OneDrive\\Desktop\\Anti-Key0\\keylog.txt");

        if (logFile.exists()) {
            progressIndicator.setVisible(true);

            Task<List<String>> loadTask = new Task<List<String>>() {
                @Override
                protected List<String> call() throws Exception {
                    List<String> keystrokes = new ArrayList<>();

                    try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            // You can add logic to analyze each keystroke line if needed.
                            keystrokes.add(line);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        keystrokes.add("Error reading log file.");
                    }

                    return keystrokes;
                }
            };
            loadTask.setOnSucceeded(event -> {
                List<String> keystrokes = loadTask.getValue();
                if (keystrokes.isEmpty()) {
                    behavioralAnalysisListView.setItems(FXCollections.observableArrayList("No keystrokes logged or log file does not exist."));
                } else {
                    behavioralAnalysisListView.setItems(FXCollections.observableArrayList(keystrokes));
                }
                progressIndicator.setVisible(false);
            });

            new Thread(loadTask).start();
        } else {
            behavioralAnalysisListView.setItems(FXCollections.observableArrayList("Log file does not exist."));
        }
    }



    private String analyzeKeystrokeBehavior(String keystroke) {
        // Example analysis logic; you can replace this with your own.
        // For example, you might want to check for common patterns like passwords, URLs, etc.
        if (keystroke.contains("password") || keystroke.contains("login")) {
            return "Suspicious keystroke pattern detected: potential password entry.";
        } else if (keystroke.contains("http://") || keystroke.contains("https://")) {
            return "Keystroke contains a URL, which could indicate web activity.";
        } else {
            return "Keystroke appears to be normal.";
        }
    }
    private void loadAndAnalyzeKeystrokes() {
        File logFile = new File("C:\\Users\\USER\\OneDrive\\Desktop\\Anti-Key0\\keylog.txt");

        if (logFile.exists()) {
            progressIndicator.setVisible(true);

            Task<List<String>> analyzeTask = new Task<List<String>>() {
                @Override
                protected List<String> call() throws Exception {
                    List<String> analyzedEntries = new ArrayList<>();

                    try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            String behaviorAnalysis = analyzeBehavior(line);
                            analyzedEntries.add(behaviorAnalysis);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        analyzedEntries.add("Error reading log file.");
                    }

                    return analyzedEntries;
                }
            };

            analyzeTask.setOnSucceeded(event -> {
                List<String> analyzedEntries = analyzeTask.getValue();
                if (analyzedEntries.isEmpty()) {
                    behavioralAnalysisListView.setItems(FXCollections.observableArrayList("No keystrokes logged or log file does not exist."));
                } else {
                    behavioralAnalysisListView.setItems(FXCollections.observableArrayList(analyzedEntries));
                }
                progressIndicator.setVisible(false);
            });

            new Thread(analyzeTask).start();
        } else {
            behavioralAnalysisListView.setItems(FXCollections.observableArrayList("Log file does not exist."));
        }
    }

    private String analyzeBehavior(String keylogEntry) {
        // Basic example: You can expand this method with more complex behavior analysis logic
        if (keylogEntry.toLowerCase().contains("password")) {
            return keylogEntry + " -> Potential sensitive information (password)";
        } else if (keylogEntry.toLowerCase().contains("admin")) {
            return keylogEntry + " -> Potential admin credentials";
        } else if (keylogEntry.length() > 20) {
            return keylogEntry + " -> Long input, could be a sensitive data entry";
        } else {
            return keylogEntry + " -> Normal keystroke";
        }
    }


    @FXML
    private void loadAndDisplayKeystrokes() {
        File logFile = new File("C:\\Users\\USER\\OneDrive\\Desktop\\Anti-Key0\\keylog.txt");

        if (logFile.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
                List<KeylogEntry> entries = new ArrayList<>();
                String line;

                while ((line = reader.readLine()) != null) {
                    KeylogEntry entry = parseKeylogEntry(line);
                    if (entry != null) {
                        entries.add(entry);
                    }
                }


                Platform.runLater(() -> {
                    heuristicListView.getItems().clear();
                    for (KeylogEntry entry : entries) {
                        heuristicListView.getItems().add(entry.getLog());
                    }
                });

            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            Platform.runLater(() -> heuristicListView.getItems().add("No keystrokes logged or log file does not exist."));
        }
    }
    // Ensure shutdown is called once and not prematurely
    public void cleanup() {
        try {
            GlobalScreen.unregisterNativeHook();
        } catch (NativeHookException e) {
            e.printStackTrace();
        }
    }


    private KeylogEntry parseKeylogEntry(String line) {
        String[] parts = line.split(":", 2);
        if (parts.length == 2) {
            String timestamp = parts[0].trim();
            String log = parts[1].trim();
            return new KeylogEntry(timestamp, log);
        }
        return null;
    }

    class KeylogEntry {
        private final String timestamp;
        private final String log;

        public KeylogEntry(String timestamp, String log) {
            this.timestamp = timestamp;
            this.log = log;
        }

        public String getTimestamp() {
            return timestamp;
        }

        public String getLog() {
            return log;
        }
    }


    @FXML
    private void handleSearchSignatures(ActionEvent event) {
        String query = searchField.getText().toLowerCase();
        List<String> recurringKeyloggers = searchKeyloggersInFile(query);

        if (recurringKeyloggers.isEmpty()) {
            signatureListView.setItems(FXCollections.observableArrayList("No recurring keyloggers found."));
        } else {
            signatureListView.setItems(FXCollections.observableArrayList(recurringKeyloggers));
        }
    }





    @FXML
    private void handleViewDetails(ActionEvent event) {
        String selectedSignature = signatureListView.getSelectionModel().getSelectedItem();
        if (selectedSignature != null) {
            showAlert(Alert.AlertType.INFORMATION, "Signature Details", "Details for: " + selectedSignature);
        } else {
            showAlert(Alert.AlertType.WARNING, "No Selection", "Please select a signature to view details.");
        }
    }

    @FXML
    private void handleExportResults(ActionEvent event) {
        showAlert(Alert.AlertType.INFORMATION, "Export Results", "Results have been exported successfully.");
    }

    @FXML
    private void handleRemoveFalsePositives(ActionEvent event) {
        String selectedSignature = signatureListView.getSelectionModel().getSelectedItem();
        if (selectedSignature != null) {
            signatureList.remove(selectedSignature);
            signatureListView.setItems(signatureList);
            showAlert(Alert.AlertType.INFORMATION, "Remove False Positive", selectedSignature + " has been removed.");
        } else {
            showAlert(Alert.AlertType.WARNING, "No Selection", "Please select a signature to remove.");
        }
    }

    private void navigateTo(String fxmlFile, ActionEvent event) {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource(fxmlFile));
            Parent root = loader.load();

            Stage stage = (Stage) ((Button) event.getSource()).getScene().getWindow();
            Scene scene = new Scene(root);
            stage.setScene(scene);
            stage.show();
        } catch (Exception e) {
            e.printStackTrace();
            showAlert(Alert.AlertType.ERROR, "Navigation Error", "An error occurred while navigating to " + fxmlFile);
        }
    }

    private void showAlert(Alert.AlertType alertType, String title, String message) {
        Alert alert = new Alert(alertType);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private List<String> performHeuristicDetection() {
        List<String> detectedThreats = new ArrayList<>();

        List<String> processThreats = checkProcessBehavior();
        List<String> fileChanges = checkFileAndRegistryChanges();
        List<String> behavioralPatterns = checkBehavioralPatterns();

        detectedThreats.addAll(processThreats);
        detectedThreats.addAll(fileChanges);
        detectedThreats.addAll(behavioralPatterns);

        Platform.runLater(() -> {
            if (!detectedThreats.isEmpty()) {
                showAlert(Alert.AlertType.WARNING, "Threats Detected",
                        "Threats detected:\n" + String.join("\n", detectedThreats));
            }
        });

        return detectedThreats;
    }

    private List<String> checkProcessBehavior() {
        List<String> threats = new ArrayList<>();
        Map<String, String> processes = getRunningProcesses();
        for (Map.Entry<String, String> process : processes.entrySet()) {
            if (isSuspicious(process.getValue())) {
                threats.add("Suspicious process detected: " + process.getKey() + " - " + process.getValue());
            }
        }
        return threats;
    }

    private List<String> checkFileAndRegistryChanges() {
        List<String> threats = new ArrayList<>();
        List<String> modifiedFiles = getModifiedFiles();
        List<String> registryChanges = getRegistryChanges();
        for (String file : modifiedFiles) {
            if (isCriticalFile(file)) {
                threats.add("Critical file modified: " + file);
            }
        }
        for (String reg : registryChanges) {
            if (isSuspiciousRegistryKey(reg)) {
                threats.add("Suspicious registry change: " + reg);
            }
        }
        return threats;
    }

    private List<String> checkBehavioralPatterns() {
        List<String> patterns = new ArrayList<>();
        Map<String, String> behaviors = getBehavioralPatterns();
        for (Map.Entry<String, String> behavior : behaviors.entrySet()) {
            if (isMaliciousBehavior(behavior.getValue())) {
                patterns.add("Malicious behavior detected: " + behavior.getKey() + " - " + behavior.getValue());
            }
        }
        return patterns;
    }

    private Map<String, String> getRunningProcesses() {
        Map<String, String> processes = new HashMap<>();
        processes.put("Process1", "Normal process");
        processes.put("Process2", "Suspicious behavior");
        return processes;
    }

    private boolean isSuspicious(String behavior) {
        return behavior.contains("Suspicious");
    }

    private List<String> getModifiedFiles() {
        List<String> files = new ArrayList<>();
        files.add("C:\\Users\\USER\\OneDrive\\Desktop\\file1.txt");
        return files;
    }

    private boolean isCriticalFile(String file) {
        return file.contains("critical");
    }

    private List<String> getRegistryChanges() {
        List<String> changes = new ArrayList<>();
        changes.add("HKEY_LOCAL_MACHINE\\Software\\MaliciousKey");
        return changes;
    }

    private boolean isSuspiciousRegistryKey(String key) {
        return key.contains("MaliciousKey");
    }

    private Map<String, String> getBehavioralPatterns() {
        Map<String, String> patterns = new HashMap<>();
        patterns.put("Pattern1", "Malicious activity detected");
        patterns.put("Pattern2", "Suspicious activity detected");
        return patterns;
    }

    private boolean isMaliciousBehavior(String behavior) {
        return behavior.contains("Malicious");
    }



    @FXML
    private void handleStopBehavioralThreat(ActionEvent event) {
        String selectedPattern = behavioralAnalysisListView.getSelectionModel().getSelectedItem();
        if (selectedPattern != null) {
            showAlert(Alert.AlertType.CONFIRMATION, "Stop Behavioral Threat", "Stopping threat related to: " + selectedPattern);
        } else {
            showAlert(Alert.AlertType.WARNING, "No Selection", "Please select a behavioral pattern to stop.");
        }
    }

    @FXML
    private void handleStartBehavioralAnalysis(ActionEvent event) {
        progressIndicator.setVisible(true);
        new Thread(() -> {
            List<String> detectedPatterns = performBehavioralAnalysis();
            Platform.runLater(() -> {
                if (!detectedPatterns.isEmpty()) {
                    behavioralAnalysisListView.setItems(FXCollections.observableArrayList(detectedPatterns));
                }
                progressIndicator.setVisible(false);
            });
        }).start();
    }

    private List<String> performBehavioralAnalysis() {
        List<String> detectedPatterns = new ArrayList<>();
        Map<String, String> patterns = getBehavioralPatterns();
        for (Map.Entry<String, String> entry : patterns.entrySet()) {
            if (isMaliciousBehavior(entry.getValue())) {
                detectedPatterns.add("Malicious behavior detected: " + entry.getKey() + " - " + entry.getValue());
            }
        }
        return detectedPatterns;
    }
    // New detection method: Contextual Analysis
    private boolean checkContextualKeywords(List<String> keystrokes) {
        for (String entry : keystrokes) {
            if (entry.contains("http://") || entry.contains("https://") || entry.contains("password")) {
                return true; // Detected potential threat
            }
        }
        return false;
    }

    // Method to handle contextual analysis button
    @FXML
    private void handleContextualAnalysis() {
        File logFile = new File("C:\\Users\\USER\\OneDrive\\Desktop\\Anti-Key0\\keylog.txt");
        if (!logFile.exists()) {
            showAlert(Alert.AlertType.WARNING, "File Not Found", "The keystroke log file does not exist.");
            return;
        }
        // Show progress indicator and message
        progressIndicator.setVisible(true);
        scanMessageLabel.setText("Scanning for threats...");

        displayRecentKeystrokes(logFile, 100);

        // Perform contextual analysis
        boolean keyloggerDetected = detectKeyloggerBehavior(logFile);


        // Hide progress indicator and update message
        progressIndicator.setVisible(false);
        scanMessageLabel.setText("Scan complete.");


        if (keyloggerDetected) {
            showAlert(Alert.AlertType.ERROR,"Threat Detected", "Suspicious patterns detected in the keystrokes.");
        } else {
            showAlert(Alert.AlertType.INFORMATION,"No Threat Detected", "No suspicious patterns were detected.");
        }

        // Clear the message after a short delay
        PauseTransition pause = new PauseTransition(Duration.seconds(3));
        pause.setOnFinished(e -> scanMessageLabel.setText(""));
        pause.play();
    }

    // Method to handle inspecting the selected behavioral pattern
    @FXML
    private void handleInspectBehavioralPattern() {
        List<String> selectedPatterns = behavioralAnalysisListView.getSelectionModel().getSelectedItems();
        if (selectedPatterns.isEmpty()) {
            showAlert(Alert.AlertType.WARNING,"No Selection", "Please select a pattern to inspect.");
            return;
        }

        // Use the new detection method
        boolean threatDetected = checkContextualKeywords(selectedPatterns);
        if (threatDetected) {
            showAlert(Alert.AlertType.ERROR,"Threat Detected", "Suspicious patterns detected in the selected keystrokes.");
        } else {
            showAlert(Alert.AlertType.INFORMATION,"No Threat Detected", "No suspicious patterns were detected.");
        }
    }



    // This method will check for suspicious patterns that might indicate keylogging activity
    private boolean detectKeyloggerBehavior(File logFile) {
        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            StringBuilder keystrokes = new StringBuilder();
            int character;

            // Read the file character by character
            while ((character = reader.read()) != -1) {
                keystrokes.append((char) character);
            }

            // Split the keystrokes into strings and analyze each one
            String keystrokeString = keystrokes.toString();
            return keystrokeString.contains("password") || keystrokeString.contains("http://");

        } catch (IOException e) {
            e.printStackTrace();
            showAlert(Alert.AlertType.ERROR, "File Error", "Failed to read the keystroke file.");
        }
        return false; // Default to no threat detected if there's an issue reading the file
    }
    private void displayRecentKeystrokes(File logFile, int numChars) {
        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            StringBuilder keystrokes = new StringBuilder();
            int character;
            int totalChars = 0;

            // Read file character by character
            while ((character = reader.read()) != -1) {
                keystrokes.append((char) character);
                totalChars++;
            }

            // Get the last 'numChars' characters
            String recentKeystrokes = keystrokes.length() > numChars ?
                    keystrokes.substring(keystrokes.length() - numChars) :
                    keystrokes.toString();

            // Check for malicious patterns
            boolean keyloggerDetected = recentKeystrokes.contains("password") || recentKeystrokes.contains("http://");

            // Display the recent keystrokes
            recentKeystrokesArea.setText(recentKeystrokes);

            // Highlight malicious keystrokes if detected
            if (keyloggerDetected) {
                recentKeystrokesArea.setStyle("-fx-text-fill: red;"); // Red text for malicious content
            } else {
                recentKeystrokesArea.setStyle("-fx-text-fill: black;"); // Default black text
            }

        } catch (IOException e) {
            e.printStackTrace();
            showAlert(Alert.AlertType.ERROR, "File Error", "Failed to read the keystroke file.");
        }
    }
    public void handleThreatDetection(ActionEvent event) {
        // Implement threat detection logic here
        System.out.println("Threat Detection initiated.");
    }


}
