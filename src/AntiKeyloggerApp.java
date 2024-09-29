import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class AntiKeyloggerApp extends Application {

    @Override
    public void start(Stage primaryStage) {
        try {
            // Load the FXML layout
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/welcome_page.fxml"));
            Parent root = loader.load();

            // Set the title and scene
            primaryStage.setTitle("Anti Keylogger");
            Scene scene = new Scene(root, 800, 600);

            // Apply the stylesheet
            String css = getClass().getResource("/styles.css").toExternalForm();
            if (css != null) {
                scene.getStylesheets().add(css);
            } else {
                System.err.println("CSS file not found.");
            }

            // Set the scene and show the stage
            primaryStage.setScene(scene);
            primaryStage.show();

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Error loading FXML or CSS files: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}
