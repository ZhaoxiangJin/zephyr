.. _cpu_freq_thermal_cap:

CPU Frequency Thermal Cap
#########################

The CPU frequency thermal cap is an optional constraint layer for the CPU Frequency Scaling
subsystem. The active policy selects the requested P-state, and the thermal cap limits the
highest-performance P-state allowed when configured temperature trip points are active.

This keeps performance demand and thermal mitigation separate:

* the CPU frequency policy decides which P-state is desirable for the current load or pressure.
* the thermal cap decides the highest-performance P-state currently allowed by temperature.

The subsystem applies the lower-performance of those two choices before requesting the SoC
P-state driver.

Devicetree
**********

Enable the thermal cap by adding a :dtcompatible:`zephyr,cpu-freq-thermal-cap` node and enabling
:kconfig:option:`CONFIG_CPU_FREQ_THERMAL_CAP`.

Example:

.. code-block:: devicetree

   cpu_freq_thermal_cap: cpu_freq_thermal_cap {
           compatible = "zephyr,cpu-freq-thermal-cap";
           sensor = <&temp0>;
           sensor-channel = "die-temp";
           polling-delay-ms = <1000>;
           passive-polling-delay-ms = <100>;
           fail-safe-pstate = <&pstate_2>;

           trip_0 {
                   temperature-millicelsius = <85000>;
                   hysteresis-millicelsius = <5000>;
                   cap-pstate = <&pstate_1>;
           };

           trip_1 {
                   temperature-millicelsius = <95000>;
                   hysteresis-millicelsius = <3000>;
                   cap-pstate = <&pstate_2>;
           };
   };

When ``trip_0`` is active, CPU frequency requests are capped to ``pstate_1`` or lower.
When ``trip_1`` is active, requests are capped to ``pstate_2`` or lower. A cap does not
force the CPU to run at that P-state; a policy request for a lower-performance P-state
is left unchanged.

Runtime behavior
****************

Temperature sampling is done from a delayable work item because sensor drivers may use
blocking operations. The CPU frequency timer reads only the cached cap when applying
a policy result.

If temperature sampling fails repeatedly, the cap applies the configured fail-safe P-state.
If no ``fail-safe-pstate`` is provided, the lowest-performance P-state is used.
