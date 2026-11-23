PWM device power management
###########################

This test measures the output through an independent PWM capture device.
The output must stop during suspend and resume its saved waveform afterwards,
including after a TURN_OFF/TURN_ON sequence. Policy and system-managed scenarios
also check the output device's declared power-state constraints.

FRDM-MCXN947
************

Use ``frdm_mcxn947/mcxn947/cpu0`` and connect PIO2_2 (SCT0_OUT0) to
PIO2_6 (PWM1_A0). SCTimer generates the waveform; FlexPWM1 submodule 0,
channel A, measures it. Keep this connection installed for all three scenarios.
The serial console uses PIO1_8/PIO1_9 and does not share these pins.

The policy and system-managed scenarios enable LPTMR0 as a wake-up source.
The board already selects it as the system timer companion.

The test initializes the capture counter range through the unrouted FlexPWM B
channel; channel A remains capture-only. Each successful single measurement is
explicitly disarmed before the next one.

FlexPWM has no device PM callback or disabling-state declaration on this board.
The capture-device suspend and capture-policy checks are therefore skipped;
the output-device PM and output-policy checks still run. These skips do not
qualify SCTimer capture PM.

Build-only validation does not verify the jumper or the observed waveform.
Hardware runners need the ``pwm_loopback`` fixture with this board-specific
connection; an unwired board is not a valid hardware test setup.
