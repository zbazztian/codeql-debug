/**
 * @name No Results
 * @description No Results
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id noresults
 */
select "", any(int i | i = 0 and i = 1).toString()
