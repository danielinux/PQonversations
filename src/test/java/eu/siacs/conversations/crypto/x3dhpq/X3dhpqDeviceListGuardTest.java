package eu.siacs.conversations.crypto.x3dhpq;

import java.util.LinkedHashSet;
import java.util.Set;
import org.junit.Assert;
import org.junit.Test;

/**
 * Regression coverage for {@link X3dhpqService#devicesDroppedWithoutRevocation(Set, Set, Set)},
 * the pure decision logic behind the {@code publishDeviceList} "shrink guard": a devicelist
 * publish must never silently drop a previously-committed device unless it is named in an
 * explicit §8.6 revocation.
 */
public class X3dhpqDeviceListGuardTest {

    private static Set<Integer> setOf(final Integer... ids) {
        return new LinkedHashSet<>(java.util.Arrays.asList(ids));
    }

    @Test
    public void shrinkWithoutRevocationIsDetected() {
        // Arrange: device 2 was previously committed but is absent from the new set,
        // and nothing allows its removal.
        final Set<Integer> prevIds = setOf(1, 2);
        final Set<Integer> newIds = setOf(1);
        final Set<Integer> allowRemovals = setOf();

        // Act
        final Set<Integer> missing =
                X3dhpqService.devicesDroppedWithoutRevocation(prevIds, newIds, allowRemovals);

        // Assert: the dropped device is reported, so the publish would be blocked.
        Assert.assertEquals("Undeclared drop of device 2 should be detected", setOf(2), missing);
    }

    @Test
    public void shrinkWithMatchingRevocationIsAllowed() {
        // Arrange: device 2 is dropped, but explicitly allowed via revocation.
        final Set<Integer> prevIds = setOf(1, 2);
        final Set<Integer> newIds = setOf(1);
        final Set<Integer> allowRemovals = setOf(2);

        // Act
        final Set<Integer> missing =
                X3dhpqService.devicesDroppedWithoutRevocation(prevIds, newIds, allowRemovals);

        // Assert
        Assert.assertTrue(
                "Revoked device 2 should not be reported as missing", missing.isEmpty());
    }

    @Test
    public void identicalRepublishIsAllowed() {
        // Arrange: the new set exactly matches the previously committed set.
        final Set<Integer> prevIds = setOf(1, 2);
        final Set<Integer> newIds = setOf(1, 2);
        final Set<Integer> allowRemovals = setOf();

        // Act
        final Set<Integer> missing =
                X3dhpqService.devicesDroppedWithoutRevocation(prevIds, newIds, allowRemovals);

        // Assert
        Assert.assertTrue("An unchanged republish should never be blocked", missing.isEmpty());
    }

    @Test
    public void growthIsAllowed() {
        // Arrange: a new device is added, nothing is dropped.
        final Set<Integer> prevIds = setOf(1);
        final Set<Integer> newIds = setOf(1, 2);
        final Set<Integer> allowRemovals = setOf();

        // Act
        final Set<Integer> missing =
                X3dhpqService.devicesDroppedWithoutRevocation(prevIds, newIds, allowRemovals);

        // Assert
        Assert.assertTrue("A growing devicelist should never be blocked", missing.isEmpty());
    }

    @Test
    public void firstEverPublishIsAllowed() {
        // Arrange: no previously committed devices at all.
        final Set<Integer> prevIds = setOf();
        final Set<Integer> newIds = setOf(1);
        final Set<Integer> allowRemovals = setOf();

        // Act
        final Set<Integer> missing =
                X3dhpqService.devicesDroppedWithoutRevocation(prevIds, newIds, allowRemovals);

        // Assert
        Assert.assertTrue("A first-ever publish should never be blocked", missing.isEmpty());
    }

    @Test
    public void nullAllowRemovalsIsTreatedAsEmpty() {
        // Arrange: same as the undeclared-drop case, but allowRemovals is null instead
        // of an empty set — publishDeviceList()'s no-arg overload passes an empty set,
        // but the helper itself must be defensive since callers could pass null.
        final Set<Integer> prevIds = setOf(1, 2);
        final Set<Integer> newIds = setOf(1);

        // Act
        final Set<Integer> missing =
                X3dhpqService.devicesDroppedWithoutRevocation(prevIds, newIds, null);

        // Assert
        Assert.assertEquals("null allowRemovals should behave like an empty set", setOf(2), missing);
    }
}
