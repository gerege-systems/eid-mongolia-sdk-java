package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.Test;

/**
 * {@link DeviceLink#tickQr} against the CA device-link golden (eid-qr-auth-e0 / -e7 share every input except
 * elapsedSeconds): port of Go devicelink_test.go TestTickQRDeviceLink with a fake clock.
 */
public class QrTickerTest {
    @Test
    public void ticksMatchGolden() throws InterruptedException {
        Json.Obj g = DeviceLinkGoldenTest.golden();
        // As stored by the RP: a Web2App-typed input must still tick as QR.
        DeviceLinkInput in = DeviceLinkGoldenTest.input(g, "eid-qr-auth-e0", Duration.ZERO).toBuilder()
            .deviceLinkType(DeviceLinkType.WEB2APP).now(null).build();
        FakeRp.FakeClock clock = new FakeRp.FakeClock(DeviceLinkGoldenTest.RECEIVED_AT);
        List<String> links = new ArrayList<>();
        List<Duration> sleeps = new ArrayList<>();
        try {
            DeviceLink.tickQr(in, Duration.ofSeconds(1), l -> {
                links.add(l);
                if (links.size() == 8) Thread.currentThread().interrupt();
            }, clock, d -> {
                sleeps.add(d);
                clock.advance(d);
            });
            fail("blocks until interrupted");
        } catch (InterruptedException expected) {
            assertTrue("the interrupt is consumed by the exception", !Thread.currentThread().isInterrupted());
        }
        assertEquals(8, links.size());
        assertEquals(DeviceLinkGoldenTest.vector(g, "eid-qr-auth-e0").optString("deviceLink"), links.get(0));
        assertEquals(DeviceLinkGoldenTest.vector(g, "eid-qr-auth-e7").optString("deviceLink"), links.get(7));
        for (int i = 0; i < 8; i++) assertTrue(links.get(i), links.get(i).contains("deviceLinkType=QR&elapsedSeconds=" + i + "&"));
        for (Duration d : sleeps) assertEquals(Duration.ofSeconds(1), d);
    }

    /** A slow consumer: missed ticks are dropped, the next tick is on the interval grid. */
    @Test
    public void slowConsumerDropsTicks() throws InterruptedException {
        Json.Obj g = DeviceLinkGoldenTest.golden();
        DeviceLinkInput in = DeviceLinkGoldenTest.input(g, "eid-qr-auth-e0", Duration.ZERO);
        FakeRp.FakeClock clock = new FakeRp.FakeClock(DeviceLinkGoldenTest.RECEIVED_AT);
        List<String> links = new ArrayList<>();
        List<Duration> sleeps = new ArrayList<>();
        try {
            DeviceLink.tickQr(in, null, l -> {
                links.add(l);
                clock.advance(Duration.ofMillis(2500)); // onLink takes 2.5 s
                if (links.size() == 3) Thread.currentThread().interrupt();
            }, clock, d -> {
                sleeps.add(d);
                clock.advance(d);
            });
            fail();
        } catch (InterruptedException expected) {
            // ok
        }
        assertEquals(List.of(Duration.ofMillis(500), Duration.ofMillis(500)), sleeps);
        assertTrue(links.get(1).contains("&elapsedSeconds=3&"));
        assertTrue(links.get(2).contains("&elapsedSeconds=6&"));
    }

    // Go TestTickQRDeviceLink: invalid input → the first tick throws, nothing emitted
    @Test
    public void invalidInputFailsFirstTick() throws InterruptedException {
        DeviceLinkInput in = DeviceLinkGoldenTest.input(DeviceLinkGoldenTest.golden(), "eid-qr-auth-e0", Duration.ZERO)
            .toBuilder().sessionSecret("").build();
        List<String> links = new ArrayList<>();
        try {
            DeviceLink.tickQr(in, Duration.ZERO, links::add);
            fail();
        } catch (EidException.DeviceLink expected) {
            assertTrue(links.isEmpty());
        }
    }

    /** The real clock and sleep: cancelled through the future's interrupt. */
    @Test
    public void realTimeCancel() throws Exception {
        DeviceLinkInput in = DeviceLinkGoldenTest.input(DeviceLinkGoldenTest.golden(), "eid-qr-auth-e0", Duration.ZERO)
            .toBuilder().receivedAt(Instant.now()).build();
        List<String> links = java.util.Collections.synchronizedList(new ArrayList<>());
        Thread t = new Thread(() -> {
            try {
                DeviceLink.tickQr(in, Duration.ofMillis(5), links::add);
            } catch (InterruptedException e) {
                // stopped
            }
        });
        t.start();
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (links.size() < 3 && System.nanoTime() < until) Thread.sleep(5);
        t.interrupt();
        t.join(5000);
        assertTrue("stopped", !t.isAlive());
        assertTrue("ticks " + links.size(), links.size() >= 3);
        assertTrue(links.get(0).contains("deviceLinkType=QR&elapsedSeconds=0&"));
    }
}
