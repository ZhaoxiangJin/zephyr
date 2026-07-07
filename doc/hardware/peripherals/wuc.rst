.. _wuc_api:

Wakeup Controller (WUC)
#######################

Overview
********

The Wakeup Controller (WUC) API provides a common interface for enabling and
managing wakeup sources that can bring the system out of low-power states.
WUC devices are typically described in Devicetree and referenced by clients
using :c:struct:`wuc_dt_spec`.

Devicetree Configuration
************************

Wakeup controllers are referenced from client nodes with the ``wakeup-ctrls``
property. The property encodes a phandle to the WUC device and an identifier
for the wakeup source.

Example Devicetree fragment:

.. code-block:: devicetree

   wuc0: wakeup-controller@40000000 {
       compatible = "nxp,mcx-wuc";
       reg = <0x40000000 0x1000>;
       #wakeup-ctrl-cells = <1>;
   };

   button0: button@0 {
       wakeup-ctrls = <&wuc0 10>;
   };

Basic Operation
***************

A client (typically a peripheral driver, see `Relationship to device power
management`_ below) obtains a :c:struct:`wuc_dt_spec` using
:c:macro:`WUC_DT_SPEC_GET` and then enables or disables the wakeup source as
needed.

.. code-block:: c
   :caption: Enable a wakeup source from Devicetree

   #define BUTTON0_NODE DT_NODELABEL(button0)

   static const struct wuc_dt_spec button_wuc =
       WUC_DT_SPEC_GET(BUTTON0_NODE);

   if (!device_is_ready(button_wuc.dev)) {
       return -ENODEV;
   }

   return wuc_enable_wakeup_source_dt(&button_wuc);

If a driver supports it, clients can check and clear a wakeup source's
triggered state. When not implemented, the APIs return ``-ENOSYS``.

.. code-block:: c
   :caption: Check and clear a wakeup source

   int ret;

   ret = wuc_check_wakeup_source_triggered_dt(&button_wuc);
   if (ret > 0) {
       (void)wuc_clear_wakeup_source_triggered_dt(&button_wuc);
   }

Relationship to device power management
***************************************

The WUC API is a **driver-facing** building block, not the interface an
application should normally use to pick its wakeup sources. Applications select
wakeup sources with the portable :ref:`device wakeup capability
<pm-device-wakeup>` API - :c:func:`pm_device_wakeup_enable` on a device whose
Devicetree node has the ``wakeup-source`` property - and the device's driver
translates that into the WUC calls above:

* The peripheral's driver keeps a :c:struct:`wuc_dt_spec` obtained from its
  ``wakeup-ctrls`` property. When the application has enabled the device as a
  wakeup source (:c:func:`pm_device_wakeup_is_enabled`), the driver arms the
  WUC line before the system enters the low-power state, and on exit uses
  :c:func:`wuc_check_wakeup_source_triggered_dt` /
  :c:func:`wuc_clear_wakeup_source_triggered_dt` to turn the latched wakeup back
  into the peripheral's normal event.
* Arming on every entry to the low-power state also transparently re-arms
  silicon that clears its WUC configuration on each wakeup reset.

The :dtcompatible:`gpio-keys` driver follows this pattern for buttons. Direct
use of the WUC API is reserved for system components that are always their own
wakeup source - such as the system-timer companion, which arms its own WUC line
during initialization - or for applications that deliberately manage a wakeup
source themselves.

API Reference
*************

.. doxygengroup:: wuc_interface
