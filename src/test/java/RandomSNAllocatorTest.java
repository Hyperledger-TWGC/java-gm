import org.junit.Test;
import twgc.gm.random.RandomSNAllocator;

import static org.junit.Assert.*;

public class RandomSNAllocatorTest {
    @Test(expected = IllegalArgumentException.class)
    public void testInvalidData() {
        new RandomSNAllocator(64);
        // should throw IllegalArgumentException
    }
}