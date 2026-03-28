# Zabbix Database Initialization

The Zabbix database schema is handled by the vulhub image entrypoint.
The MySQL container initializes with the `zabbix` database via the `MYSQL_DATABASE` environment variable,
and the Zabbix server container populates the schema on first startup.

No additional SQL init scripts are required in this directory.
