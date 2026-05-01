.. _pressure_policy:

Pressure based CPU Frequency Scaling Policy
###########################################

The pressure policy evaluates the current pressure of the ready queue in order to inform system
P-state transitions.

Thread pressure is calculated by the following formula:

.. math::

   P_{sys} = \frac{\sum_{t \in R} (P_{min} - prio_t + 1)}
                   {\sum_{t \in T} (P_{min} - prio_t + 1)} \times 100

where

- :math:`R` is the set of runnable (queued) threads
- :math:`T` is the set of all threads considered for pressure
- :math:`w_t = P_{min} - \text{prio}_t + 1` is the weight of thread :math:`t`
- :math:`P_{min}` is the configured minimum priority to consider (the highest value numerically)

This produces a normalized system pressure between 0 and 100 which is then used to select an
appropriate P-state as defined by the SoC or overlay file.

When :kconfig:option:`CONFIG_CPU_FREQ_POLICY_PRESSURE_RUNTIME_HISTORY` is enabled, the policy
blends this instantaneous runnable-thread pressure with the non-idle CPU runtime measured over
the previous CPU frequency evaluation window. This keeps short-lived queue bursts from being
treated as sustained CPU pressure when the recent execution history shows little actual CPU
demand. The blend is controlled by :kconfig:option:`CONFIG_CPU_FREQ_POLICY_PRESSURE_RUNTIME_HISTORY_WEIGHT`.

The effective pressure is computed as:

.. math::

   P_{eff} = \frac{P_{sys} \times (100 - W) + P_{rt} \times W}{100}

where :math:`W` is :kconfig:option:`CONFIG_CPU_FREQ_POLICY_PRESSURE_RUNTIME_HISTORY_WEIGHT`
and :math:`P_{rt}` is the percentage of the previous evaluation window during which the CPU
executed non-idle work.

A weight of ``0`` preserves the snapshot-only behavior; a weight of ``100`` bases the
pressure score entirely on recent non-idle CPU runtime. Note that the policy is still only
invoked when the CPU frequency framework evaluates it, so the runnable-thread snapshot is
always required to drive evaluation - a weight of ``100`` does not disable that path.

This feature relies on the kernel's runtime statistics. When
:kconfig:option:`CONFIG_CPU_FREQ_POLICY_PRESSURE_RUNTIME_HISTORY` is enabled,
:kconfig:option:`CONFIG_THREAD_RUNTIME_STATS` is selected automatically. The very first
invocation after boot, as well as any window in which the cycle counters were reset, falls
back to the instantaneous pressure value.

Once the normalized system pressure is calculated, it is treated as the system 'load' and the
policy will then iterate through the available P-states of the SoC and select the first P-state
for which the normalized pressure is greater than or equal to the defined threshold.

If no P-state matches (i.e., the normalized pressure is below all thresholds), the policy will select the
last P-state in the soc_pstates array (the lowest performance state).

The user may tune the responsiveness of this policy by adjusting
the :kconfig:option:`CONFIG_CPU_FREQ_POLICY_PRESSURE_LOWEST_PRIO` option which should be set the priority
of the lowest priority thread in the system (which numerically would be the highest number). The pressure
policy will ignore threads of lower priority than this option, and due to the formulae above, will change
the perceived impact of a high-priority thread running.

For an example of the pressure policy, refer to the :zephyr:code-sample:`cpu_freq_pressure` sample.

This policy attempts to be proactive in evaluating queued tasks and adjusting the clock frequency
ahead of their execution time, although this policy makes no guarantees on performance or determinism
of threads achieving their deadlines and avoiding starvation.

Note that the :kconfig:option:`CONFIG_CPU_FREQ_POLICY_PRESSURE_LOWEST_PRIO` includes :kconfig:option:`CONFIG_TRACING`
introduces overhead to context switching.
