import semmle.javascript.dependencies.Dependencies

predicate externalDependencies(Dependency dep, string name, int ndeps) {
  exists(string id, string v | dep.info(id, v) | name = id + "-" + v) and
  ndeps = count(Locatable use | use = dep.getAUse(_))
}

from Dependency dep, string name, int ndeps
where externalDependencies(dep, name, ndeps)
select name, ndeps order by ndeps desc
