/**
 * @name Path Traversal in ClientEventLogger (CVE-2023-30626)
 * @description Finds Path.Combine used with interpolated strings, indicating potential path traversal.
 * @kind problem
 * @problem.severity error
 * @id cs/custom/path-traversal-jellyfin
 */
import csharp

from MethodAccess ma, InterpolatedString ip
where
  // 1. Ищем вызов метода Combine
  ma.getTarget().hasName("Combine") and
  // 2. Который принадлежит классу Path
  ma.getTarget().getDeclaringType().hasName("Path") and
  // 3. Который находится в пространстве имен System.IO
  ma.getTarget().getDeclaringType().getNamespace().hasName("System.IO") and
  // 4. И хотя бы один из аргументов является интерполированной строкой ($"...")
  (ma.getArgument(0) = ip or ma.getArgument(1) = ip)
select ma, "CVE-2023-30626: Path.Combine is called with an interpolated string, creating a path traversal risk."
