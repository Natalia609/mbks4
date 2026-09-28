/**
 * @name Simple Path Traversal Detection (CVE-2023-30626)
 * @kind problem
 * @problem.severity error
 */
import csharp

from MethodAccess ma
where
  // Ищем вызов метода с именем "Combine"
  ma.getTarget().hasName("Combine") and
  // Который принадлежит классу "Path"
  ma.getTarget().getDeclaringType().hasName("Path") and
  // Который находится в пространстве имен "System.IO"
  ma.getTarget().getDeclaringType().getNamespace().hasName("System.IO")
select ma, "CVE-2023-30626: Path.Combine detected. Check if arguments are sanitized with Path.GetFullPath()."
