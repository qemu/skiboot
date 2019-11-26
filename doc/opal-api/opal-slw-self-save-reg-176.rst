.. OPAL_SLW_SELF_SAVE_REG:

OPAL_SLW_SELF_SAVE_REG
======================

.. code-block:: c

   #define OPAL_SLW_SELF_SAVE_REG			176

   int64_t opal_slw_self_save_reg(uint64_t cpu_pir, uint64_t sprn);

:ref:`OPAL_SLW_SELF_SAVE_REG` is used to inform low-level firmware to save
the current contents of the SPR before entering a state of loss and
also restore the content back on waking up from a deep stop state.

Parameters
----------

``uint64_t cpu_pir``
  This parameter specifies the pir of the cpu for which the call is being made.
``uint64_t sprn``
  This parameter specifies the spr number as mentioned in p9_stop_api.H for
  Power9 and p8_pore_table_gen_api.H for Power8.

Returns
-------

:ref:`OPAL_UNSUPPORTED`
  If spr restore is not supported by pore engine.
:ref:`OPAL_PARAMETER`
  Invalid handle for the pir/chip
:ref:`OPAL_SUCCESS`
  On success