UPDATE alerts SET message = REPLACE(message, 'CVE baru ', 'New CVE ');
UPDATE alerts SET message = REPLACE(message, 'rollup naik dari informasional ke kritis', 'rollup raised from informational to critical');
UPDATE alerts SET message = REPLACE(message, 'rollup naik dari ', 'rollup raised from ');
