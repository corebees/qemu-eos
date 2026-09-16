 /**
 * Minimal generic spell set based on 60D (deleted everything that did not prevent booting)
 * 
 * Without card support (comment out PROP_CARD2_EXISTS), it boots most EOS models (menu navigation works)
 * Tested on: 5D2 5D3 6D 50D 60D 70D 450D 500D 550D 600D 650D 700D 100D 1000D 1100D 1200D 1300D EOSM2.
 * Not working: EOSM.
 * Does something: 80D, 750D, 760D.
 *
 * With SD card support (unmodified - PROP_CARD2_EXISTS enabled), it initializes SD
 * on all the above EOS models, but may crash at EstimatedSize on the most recent ones.
 * Even if it crashes, the SD card is initialized and the firmware can save files to the virtual card.
 * Working (menu navigation, card format): 60D 500D 550D 600D 650D 700D 1100D 1200D 1300D.
 * Working (menu navigation, card recognized): 450D 1000D.
 * Assert at EstimatedSize, dumpf works: 5D3 6D 70D 80D 100D EOSM2.
 * Not working EOSM.
 * 
 * With CF card support (use PROP_CARD1_EXISTS, 0x21 -> 0x20):
 * Working: 50D 5D2.
 * Not working: 5D3.
 * 
 */


static struct mpu_init_spell mpu_init_spells_5D4[] = {
    { { 0x06, 0x04, 0x02, 0x00, 0x00 }, .description = "Init", .out_spells = { /* spell #1 */
        { 0x2c, 0x2a, 0x02, 0x00, 0x03, 0x03, 0x03, 0x04, 0x03, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x14, 0x50, 0x00, 0x00, 0x00, 0x00, 0x81, 0x06, 0x00, 0x00, 0x04, 0x06, 0x00, 0x00, 0x04, 0x06, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x4b, 0x01 },/* reply #1.17, Init */
        /*
         * QEMU40PAD-AM
         *
         * Canon EOS 5D Mark IV FW 1.3.3 Startup stage 5
         * registers PROP_POWER_KIND (0x80030003).
         *
         * Without an MPU value, Canon observes the initial
         * sentinel 0xFF and suppresses NotifyComplete(Startup, 1).
         *
         * Existing qemu-eos EOS models represent power kind 0 as:
         *   06 05 03 04 00 00
         *
         * Diagnostic causal test: supply the same property through
         * the normal MPU/property path; do not patch Canon state.
         */
        { 0x06, 0x05, 0x03, 0x04, 0x00, 0x00 },                 /* QEMU40PAD-AM PROP_POWER_KIND */
        { 0x06, 0x05, 0x01, 0x21, 0x01, 0x00 },                 /* reply #1.3, PROP_CARD2_EXISTS */

        /*
         * EOS 5D Mark IV FW 1.3.3 PROP_VIDEO_MODE.
         *
         * 5D4 uses the modern 0x26/0x24 MPU frame.
         * 0x09C4 was observed from Canon FW and is required
         * during startup before EstimatedSize initialization.
         */
        {
            0x26, 0x24, 0x01, 0x4e,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x09, 0xc4,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x58,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x55,
            0x80, 0x00, 0x00, 0x3f,
            0x00, 0x00
        }, /* PROP_VIDEO_MODE */

        { 0 } } },

    /*
     * QEMU40LG DIAGNOSTIC ONLY
     *
     * 5D4 FW 1.3.3 emits:
     *   08 06 00 00 02 00 00
     *
     * during PrepareProperty.
     *
     * Send the same 5D3-style PROP_ISO_RANGE previously tested
     * by QEMU40JQ, but move it from Init to the real 5D4
     * Complete WaitID boundary.
     *
     * This tests TIMING only.
     */
    {
        { 0x08, 0x06, 0x00, 0x00, 0x02, 0x00, 0x00 },
        .description = "QEMU40MN Complete WaitID ISO semantic probe",
        .out_spells = {
            /*
             * QEMU40MN diagnostic only.
             *
             * Proven 5D4 12-byte framing.
             *
             * Gmt consumes:
             *   +0 = Still MaxIso
             *   +4 = Movie MaxIso
             *   +6 = MovieEx1 MaxIso
             *   +8 = MovieEx2 MaxIso
             *
             * Preserve Movie=0x01 and MovieEx2=0x70.
             * Replace only the two CODE8_ISO_AUTO zeros that
             * causally trigger Line590 / Line624.
             */
            { 0x12, 0x10, 0x01, 0x6e,
              0x70, 0x00, 0x00, 0x00,
              0x01, 0x00, 0x70, 0x00,
              0x70, 0x00, 0x00, 0x00,
              0x00, 0x00 },
            { 0 }
        }
    },

    /*
     * QEMU40PAD R20AL DIAGNOSTIC ONLY
     *
     * Canon EOS 5D Mark IV FW 1.3.3 repeatedly emits:
     *
     *   06 05 02 0A 01 00
     *
     * PROP_PERMIT_ICU_EVENT is currently unhandled by the
     * 5D4 QEMU MPU model.
     *
     * Sister-camera models answer this exact trigger with an
     * initial PD_NotifyOlcInfoChanged block.
     *
     * For this causal probe only, use the 60D startup OLC
     * payload because the current minimal 5D4 model was itself
     * derived from the 60D model and the trigger is identical.
     *
     * IMPORTANT:
     * This payload is NOT claimed to be the correct 5D4 OLC
     * data.  It is a donor used solely to test whether supplying
     * the missing OLC producer activates Canon's OLC storage /
     * copy / renderer path.
     *
     * No GUI_Control replies and no extra properties are copied:
     * isolate PD_NotifyOlcInfoChanged causality.
     */
    {
        { 0x06, 0x05, 0x02, 0x0a, 0x01, 0x00 },
        .description = "QEMU40PAD R20AL PERMIT_ICU OLC causal probe",
        .out_spells = {
            {
                0x4e, 0x4d, 0x0a, 0x08,
                0xff, 0x1f, 0x01, 0x00,
                0x01, 0x01, 0xa0, 0x10,
                0x00, 0x4d, 0x01, 0x01,
                0x58, 0x2d, 0x4b, 0x01,
                0x01, 0x00, 0x48, 0x04,
                0x01, 0x00, 0x07, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
                /*
                 * R20AP CAUSAL PROBE ONLY:
                 *
                 * R20AO proved that the R20AL short frame
                 * overreads 12 bytes for Group11/Group12.
                 *
                 * Replay here, INSIDE the valid frame, the
                 * exact bytes actually consumed/stored by
                 * those two groups:
                 *
                 * AB 00 60 B3 A8 00 D0 B3 A8 00 20 00
                 *
                 * These are NOT claimed to be genuine 5D4
                 * OLC protocol values.
                 */
                0xab, 0x00, 0x60, 0xb3,
                0xa8, 0x00, 0xd0, 0xb3,
                0xa8, 0x00, 0x20, 0x00
            }, /* R20AP valid-length consumed-overread replay */

            /*
             * R20AU CAUSAL PROBE:
             *
             * Older EOS MPU spell tables initialize switch 18
             * with value 0 during PERMIT_ICU_EVENT.
             *
             * QEMU button tables associate switch 18 with the
             * card-door state. 5D4 Canon firmware should then
             * reach IDLEHandler CLOSE_SLOT_COVER and its
             * canonical BASE+0x74 setter.
             *
             * This frame is tested in isolation.
             */
            /*
             * R20AV CAUSAL PROBE:
             *
             * Cross-camera PERMIT_ICU initialization sequences
             * send switch17=1 immediately before switch18=0.
             *
             * R20AU already proved switch18=0 naturally produces
             * CLOSE_SLOT_COVER / BASE+0x74 = 0x1000001C.
             *
             * Test switch17=1 independently as the candidate
             * natural producer for GUI_LOCK_ON / BASE+0x78.
             */
            { 0x06, 0x05, 0x06, 0x11, 0x01, 0x00 },
            /* R20AV: bindReceiveSwitch(17,1) */

            { 0x06, 0x05, 0x06, 0x12, 0x00, 0x00 },
            /* R20AU: bindReceiveSwitch(18,0) */

            { 0 }
        }
    },

    /*
     * QEMU40PAD R20E DIAGNOSTIC ONLY
     *
     * Canon 5D IV FW 1.3.3 emits:
     *   06 05 04 0d 01 00
     *
     * Baseline 5D4 QEMU has no matching spell.
     * Older QEMU camera models answer with the same
     * PROP_ACTIVE_SWEEP_STATUS set back to zero to model
     * completion of the sensor-cleaning / ActiveSweep phase.
     *
     * Runtime causality is NOT yet established on 5D4.
     */
    {
        { 0x06, 0x05, 0x04, 0x0d, 0x01, 0x00 },
        .description = "QEMU40PAD R20E PROP_ACTIVE_SWEEP_STATUS completion",
        .out_spells = {
            { 0x06, 0x05, 0x04, 0x0d, 0x00, 0x00 },
            { 0 }
        }
    },

    #include "NotifyGUIEvent.h"
    #include "UILock.h"
    #include "CardFormat.h"
    #include "GPS.h"
    #include "Shutdown.h"
};
