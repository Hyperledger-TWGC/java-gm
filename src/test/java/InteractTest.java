import org.junit.Test;

public class InteractTest {

    @Test
    public void generateCsr() {
        try {
            Interact.generateCsr(false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}