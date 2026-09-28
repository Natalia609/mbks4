/**
 * @name Path Traversal Vulnerability (CVE-2023-30626)
 * @description Detects System.IO.Path.Combine usage which may be vulnerable to path traversal if inputs are not sanitized.
 * @kind problem
 * @problem.severity error
 * @id cs/custom/path-traversal-jellyfin
 * @tags security external/cwe/cwe-022
 */
import csharp

from MethodAccess ma
where 
  // Используем hasQualifiedName для точного поиска System.IO.Path.Combine
  ma.getTarget().hasQualifiedName("System.IO", "Path", "Combine")
select ma, "CVE-2023-30626: System.IO.Path.Combine is used. Ensure the path is sanitized using Path.GetFullPath() and validated against the base directory."
