/*
 * Note this file is here just for better readability. The real file in use is
 * capi-305.sql, whith one SQL sentence per file line.
 */

/*
 * REBUILD and REINDEX ufds_o_smartdc in order to support multi-valued columns
 * for `objectclass`, `pwdhistory` and `pwdfailuretime` (using temporary columns).
 */

ALTER TABLE ufds_o_smartdc ADD COLUMN objectclass_ary text[];
ALTER TABLE ufds_o_smartdc ADD COLUMN pwdhistory_ary text[];
ALTER TABLE ufds_o_smartdc ADD COLUMN pwdfailuretime_ary numeric[];

/* objectclass */
WITH new_values AS (
  SELECT _id,
         regexp_split_to_array(objectclass, ',') AS objectclass_arr
   FROM ufds_o_smartdc
   ORDER BY _id
)
UPDATE ufds_o_smartdc AS tr
  SET objectclass_ary = nv.objectclass_arr
FROM new_values nv
WHERE nv._id = tr._id;

/* pwdhistory */
WITH new_values AS (
  SELECT _id,
         regexp_split_to_array(pwdhistory, ',') AS pwdhistory_arr
   FROM ufds_o_smartdc
   WHERE pwdhistory IS NOT NULL
   ORDER BY _id
)
UPDATE ufds_o_smartdc AS tr
  SET pwdhistory_ary = nv.pwdhistory_arr
FROM new_values nv
WHERE nv._id = tr._id;

/* pwdfailuretime */

WITH new_values AS (
  SELECT _id,
         ARRAY[pwdfailuretime::numeric] AS pwdfailuretime_arr
   FROM ufds_o_smartdc
   WHERE pwdfailuretime IS NOT NULL
   ORDER BY _id
)
UPDATE ufds_o_smartdc AS tr
  SET pwdfailuretime_ary = nv.pwdfailuretime_arr
FROM new_values nv
WHERE nv._id = tr._id;

DROP INDEX IF EXISTS ufds_o_smartdc_objectclass_idx;
DROP INDEX IF EXISTS ufds_o_smartdc_pwdfailuretime_idx;
DROP INDEX IF EXISTS ufds_o_smartdc_pwdhistory_idx;

ALTER TABLE ufds_o_smartdc DROP COLUMN IF EXISTS objectclass;
ALTER TABLE ufds_o_smartdc DROP COLUMN IF EXISTS pwdhistory;
ALTER TABLE ufds_o_smartdc DROP COLUMN IF EXISTS pwdfailuretime;

ALTER TABLE ufds_o_smartdc RENAME COLUMN objectclass_ary to objectclass;
ALTER TABLE ufds_o_smartdc RENAME COLUMN pwdhistory_ary to pwdhistory;
ALTER TABLE ufds_o_smartdc RENAME COLUMN pwdfailuretime_ary to pwdfailuretime;

CREATE INDEX ufds_o_smartdc_objectclass_idx ON ufds_o_smartdc USING gin (objectclass) WHERE (objectclass IS NOT NULL);
CREATE INDEX ufds_o_smartdc_pwdfailuretime_idx ON ufds_o_smartdc USING gin (pwdfailuretime) WHERE (pwdfailuretime IS NOT NULL);
CREATE INDEX ufds_o_smartdc_pwdhistory_idx ON ufds_o_smartdc USING gin (pwdhistory) WHERE (pwdhistory IS NOT NULL);

REINDEX INDEX ufds_o_smartdc_objectclass_idx;
REINDEX INDEX ufds_o_smartdc_pwdfailuretime_idx;
REINDEX INDEX ufds_o_smartdc_pwdhistory_idx;
