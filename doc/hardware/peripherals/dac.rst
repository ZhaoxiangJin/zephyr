.. _dac_api:

Digital-to-Analog Converter (DAC)
#################################

Overview
********

The DAC API provides access to Digital-to-Analog Converter (DAC) devices.

Output lifetime
***************

A channel is configured once with :c:func:`dac_channel_setup`. It starts driving
its output when :c:func:`dac_write_value` is called and keeps driving it until
something stops it.

Writing zero is not a way to stop an output: it selects the bottom of the output
range, which the channel then drives just as actively as any other level.
Drivers that can stop a channel implement the optional
:c:func:`dac_channel_stop`, which leaves the channel configured, so a later
:c:func:`dac_write_value` resumes driving without a second setup. Drivers that
cannot stop a channel return ``-ENOSYS``.

The electrical state a stopped output is left in is hardware dependent. Some
devices release the pin to high impedance, on others the level is determined by
the pin configuration. Consult the binding of the device in question.

Configuration Options
*********************

Related configuration options:

* :kconfig:option:`CONFIG_DAC`

API Reference
*************

.. doxygengroup:: dac_interface
