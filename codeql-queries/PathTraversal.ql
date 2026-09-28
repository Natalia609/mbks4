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
  // 1. Проверяем, что метод принадлежит классу "Path" в пространстве имен "System.IO"
  ma.getTarget().getDeclaringType().hasQualifiedName("System.IO", "Path") and
  // 2. Проверяем, что имя самого метода - "Combine"
  ma.getTarget().hasName("Combine")
select ma, "CVE-2023-30626: System.IO.Path.Combine is used. Ensure the path is sanitized using Path.GetFullPath() and validated against the base directory."
