Mining interface
----------------

The C++ `BlockTemplate::submitSolution()` method returns the submitted `CBlock`
and reports acceptance through a `bool&` output argument. The block is returned
on both acceptance and rejection so clients can preserve it for investigation.
A null coinbase raises an exception before a block can be constructed.

The IPC reply retains the existing boolean wire slot, renames it `accepted`,
and appends the block as `result`. The method keeps ordinal 10. Clients can
check for the new block field; older nodes omit it. This reply extension is
wire-compatible, while C++ callers must adapt to the new signature.
