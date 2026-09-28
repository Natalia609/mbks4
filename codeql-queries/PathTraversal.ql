/**
 * @name Path Traversal in ClientEventLogger
 * @description Finds untrusted input flowing into Path.Combine without sanitization
 * @kind path-problem
 * @problem.severity error
 * @id cs/custom/path-traversal-jellyfin
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.security.dataflow.flowsources.RemoteFlowSources

class PathTraversalConfig extends DataFlow::Configuration {
  PathTraversalConfig() { this = "PathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getTarget().hasName("Combine") and
      ma.getTarget().getDeclaringType().hasName("Path") and
      ma.getTarget().getDeclaringType().getNamespace().hasName("System.IO") and
      (sink.asExpr() = ma.getArgument(0) or sink.asExpr() = ma.getArgument(1))
    )
  }
}

from PathTraversalConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "CVE-2023-30626: untrusted input flows into Path.Combine", source, "User input"
