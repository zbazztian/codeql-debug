import python
import semmle.python.dependencies.TechInventory

predicate package_count(ExternalPackage package, int total) {
  total =
    count(AstNode src |
      dependency(src, package) and
      src.getLocation().getFile().fromSource()
    )
}

string package_name(ExternalPackage p) {
  exists(p.getVersion()) and result = p.getName() + "(" + p.getVersion() + ")"
  or
  not exists(p.getVersion()) and result = p.getName() + "(unknown)"
}

from int total, ExternalPackage package
where package_count(package, total)
select package_name(package), total order by total desc
