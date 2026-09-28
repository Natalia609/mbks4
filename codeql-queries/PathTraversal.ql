/**
 * @name Path Traversal Risk (CVE-2023-30626)
 * @kind problem
 * @problem.severity error
 * @id cs/custom/path-traversal-jellyfin
 */
import csharp

from MethodAccess ma
where 
  ma.getTarget().hasName("Combine") and
  ma.getTarget().getDeclaringType().hasName("Path") and
  ma.getTarget().getDeclaringType().getNamespace().hasName("System.IO")
select ma, "CVE-2023-30626: System.IO.Path.Combine is used. Verify inputs are sanitized."
