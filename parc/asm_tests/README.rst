==========================================================================
PARC Assembly Tests
==========================================================================

This requires ``pydgin-parc-xcc`` (``maven-sys-xcc``) cross-compiler
installed. First, build the tests::

  % mkdir build
  % cd build
  % ../configure --host=maven
  % make

Now, you can run the tests. Failures and errors (if any) would be reported
at the very end::

  % make check
  ...
  ------------------------------------------------------------------------
  Test summary (failures and errors)
  ------------------------------------------------------------------------
  parcv2-div.out: [ FAILED ] ./parcv2-div (line 28)
  ...

This runs the interpreted pydgin by default. To test with translated
pydgin, you can specify the translated pydgin binary with ``RUN`` flag to
``make``::

  % make check RUN=../../pydgin-parc-jit

